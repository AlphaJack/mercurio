//! The delivery flow: authenticate, resolve users and rooms, then post each message and attachment and report every target.

use super::super::message_content;
#[cfg(feature = "service-matrix-e2ee")]
use super::super::{e2ee_flow, sas};
use super::*;

impl Session {
    pub fn run(mut self) -> Plan {
        if self.access_token.is_none() && self.password().is_some_and(|p| !p.is_empty()) && self.cfg.user.is_none() {
            self.access_token = self.password().map(str::to_string);
            self.txn = Txn::Uuid(self.env.uuid4());
        }
        if self.access_token.is_none() {
            return self.login(Box::new(|s, ok| {
                if ok {
                    return s.after_auth();
                }
                s.register(Box::new(|s, ok| {
                    if ok {
                        s.after_auth()
                    } else {
                        s.finish(Some(Error::Service("Matrix login and registration failed".into()).context("login")))
                    }
                }))
            }));
        }
        self.after_auth()
    }

    pub(super) fn after_auth(self) -> Plan {
        if !non_empty(&self.user_id) {
            return self.whoami(Box::new(|s, ()| s.after_identity()));
        }
        self.after_identity()
    }

    pub(super) fn after_identity(mut self) -> Plan {
        if !non_empty(&self.home_server) {
            self.home_server = Some(self.cfg.host.clone());
        }
        if self.cfg.rooms.is_empty() && self.cfg.users.is_empty() {
            return self.joined_rooms(Box::new(|mut s, rooms| {
                if rooms.is_empty() {
                    log::warn!("There were no Matrix rooms specified to notify.");
                    let e = Error::Service("there were no Matrix rooms to notify".into());
                    return s.finish(Some(e.context("room lookup")));
                }
                s.queue = rooms.into_iter().map(|r| (label_of(&r), r)).collect();
                s.resolve_users(VecDeque::new())
            }));
        }
        self.queue = self.cfg.rooms.iter().map(|r| (r.clone(), json!(r))).collect();
        let users: VecDeque<String> = self.cfg.users.iter().cloned().collect();
        self.resolve_users(users)
    }

    pub(super) fn resolve_users(mut self, mut users: VecDeque<String>) -> Plan {
        let Some(user) = users.pop_front() else { return self.after_dm_rooms() };
        if self.delivered(&user) {
            return self.resolve_users(users);
        }
        self.dm_room(
            user.clone(),
            Box::new(move |mut s, room| {
                match room {
                    Some(r) => s.queue.push_back((user, r)),
                    None => {
                        log::warn!("Could not find or create a DM room for Matrix user {user}.");
                        let e = Error::Service("could not find or create a direct-message room".into());
                        s.fail_target_with(user, e.context("room lookup"));
                    }
                }
                s.resolve_users(users)
            }),
        )
    }

    pub(super) fn after_dm_rooms(self) -> Plan {
        #[cfg(feature = "service-matrix-e2ee")]
        if self.e2ee_wanted() {
            return e2ee_flow::setup(self, Box::new(|s, ()| s.next_room()));
        }
        self.next_room()
    }

    pub fn next_room(mut self) -> Plan {
        let Some((label, room)) = self.queue.pop_front() else { return self.after_rooms() };
        if self.delivered(&label) {
            return self.next_room();
        }
        self.room_join(
            room,
            Box::new(move |mut s, room_id| match room_id {
                None => {
                    log::warn!("Could not join Matrix room {label}.");
                    s.fail_target_with(label, Error::Service("could not join the room".into()).context("room join"));
                    s.next_room()
                }
                Some(rid) => s.deliver(label, rid),
            }),
        )
    }

    pub(super) fn deliver(self, label: String, room_id: String) -> Plan {
        // With E2EE wanted, a room is sent plaintext only after the server said it has no encryption state; an encrypted room never gets plaintext, even when E2EE setup failed.
        #[cfg(feature = "service-matrix-e2ee")]
        if self.e2ee_wanted() {
            return e2ee_flow::room_encrypted(
                self,
                room_id.clone(),
                Box::new(move |mut s, encrypted| match encrypted {
                    Ok(false) => s.deliver_plain(label, room_id),
                    Ok(true) if s.e2ee.capable => e2ee_flow::deliver_encrypted(s, label, room_id),
                    Ok(true) => {
                        log::warn!("Matrix room {label} is encrypted but E2EE is unavailable; message not sent.");
                        let e = s
                            .e2ee
                            .setup_error
                            .clone()
                            .unwrap_or_else(|| Error::Service("Matrix E2EE setup failed".into()));
                        s.fail_target_with(label, e);
                        s.next_room()
                    }
                    Err(e) => {
                        s.fail_target_with(label, e);
                        s.next_room()
                    }
                }),
            );
        }
        self.deliver_plain(label, room_id)
    }

    pub(super) fn message_path(&self, room_id: &str) -> String {
        format!("/rooms/{}/send/m.room.message/{}", quote_path(room_id), self.txn)
    }

    /// Unencrypted delivery to one room.
    pub(super) fn deliver_plain(self, label: String, room_id: String) -> Plan {
        if !self.msg.attachments.is_empty() && self.attachments.is_none() {
            return self.upload_attachments(Box::new(move |s, ok| {
                if ok {
                    s.deliver_plain(label, room_id)
                } else {
                    s.finish(Some(Error::Service("Matrix attachment upload failed".into()).context("upload")))
                }
            }));
        }
        if let Some(image) = self.msg.image_url.clone()
            && self.cfg.version == Version::V2
        {
            let body =
                if self.msg.title.is_empty() { self.msg.kind.as_str().to_string() } else { self.msg.title.clone() };
            let payload = json!({"msgtype": "m.image", "url": image, "body": body});
            let path = self.message_path(&room_id);
            return self.fetch(Fetch::put(path, payload), move |mut s, r| {
                if !r.ok {
                    s.fail_target_with(label, Error::Service("image post failed".into()).context("send"));
                    return s.next_room();
                }
                s.bump_txn();
                s.post_attachments(label, room_id, 0, false)
            });
        }
        self.post_attachments(label, room_id, 0, false)
    }

    pub(super) fn post_attachments(mut self, label: String, room_id: String, idx: usize, target_error: bool) -> Plan {
        let payload = match self.attachments.as_mut().and_then(|a| a.get_mut(idx)) {
            Some(p) => {
                p["room_id"] = json!(room_id);
                p["type"] = json!("m.room.message");
                p.clone()
            }
            None => return self.post_message(label, room_id, target_error),
        };
        let path = self.message_path(&room_id);
        self.fetch(Fetch::put(path, payload), move |mut s, r| {
            s.bump_txn();
            s.post_attachments(label, room_id, idx + 1, target_error || !r.ok)
        })
    }

    pub(super) fn post_message(self, label: String, room_id: String, target_error: bool) -> Plan {
        let payload = message_content(&self.cfg, &self.msg);
        let path = self.message_path(&room_id);
        self.fetch(Fetch::put(path, payload), move |mut s, r| {
            s.bump_txn();
            if !r.ok {
                log::warn!("Could not send notification Matrix room {label}.");
                // Keeps the failure's class: a 5xx is retried, a 4xx or a request that may have been sent is not.
                s.fail_target_with(label, r.error("message post failed").context("send"));
            } else if target_error {
                s.fail_target_with(label, Error::Service("attachment post failed".into()).context("send"));
            } else {
                s.ok_target(label);
            }
            s.next_room()
        })
    }

    pub(super) fn after_rooms(self) -> Plan {
        #[cfg(feature = "service-matrix-e2ee")]
        if self.e2ee.capable && self.cfg.autoverify && self.outcomes.iter().all(|(_, e)| e.is_none()) {
            sas::refresh_verified_state(&self);
        }
        self.finish(None)
    }

    /// End of `send()`. The session stays open; [`Session::logout`] runs when the target is closed.
    pub fn finish(mut self, fatal: Option<Error>) -> Plan {
        let fatal = fatal.map(|e| self.rate_limited(e));
        let done = move |s: Session| -> Plan {
            if let Some(e) = fatal {
                return Plan::Fail(e);
            }
            if s.outcomes.is_empty() {
                return Plan::Done;
            }
            Plan::all(s.outcomes.into_iter().map(|(label, e)| match e {
                None => Plan::Done.target(label),
                Some(e) => Plan::Fail(e).target(label),
            }))
        };
        done(self)
    }

    /// Upload every attachment once.
    pub(super) fn upload_attachments(self, k: K<bool>) -> Plan {
        self.upload_one(0, Vec::new(), k)
    }

    pub(super) fn upload_one(self, idx: usize, mut payloads: Vec<Value>, k: K<bool>) -> Plan {
        let Some(att) = self.msg.attachments.get(idx).cloned() else {
            let mut s = self;
            s.attachments = Some(payloads);
            return k(s, true);
        };
        let is_image = att.mime.to_ascii_lowercase().starts_with("image/");
        if !is_image && self.cfg.version == Version::V2 {
            return self.upload_one(idx + 1, payloads, k);
        }
        let f = Fetch::upload(&att.name, &att.mime, Arc::new(att.data.to_vec()));
        self.fetch(f, move |s, r| {
            let Some(resp) = r.object() else { return k(s, false) };
            let uri = resp.get("content_uri").cloned().unwrap_or(Value::Null);
            if s.cfg.version == Version::V3 {
                let mut p = json!({
                    "body": att.name,
                    "info": {"mimetype": att.mime, "size": att.data.len()},
                    "msgtype": if is_image { "m.image" } else { "m.file" },
                    "url": uri,
                });
                if !is_image {
                    p["filename"] = json!(att.name);
                }
                payloads.push(p);
            } else {
                payloads.push(json!({
                    "info": {"mimetype": att.mime},
                    "msgtype": "m.image",
                    "body": "tta.webp",
                    "url": uri,
                }));
            }
            s.upload_one(idx + 1, payloads, k)
        })
    }
}
