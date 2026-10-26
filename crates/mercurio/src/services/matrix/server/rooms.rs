//! Which rooms to post to: joined rooms, joining by id or alias, creating rooms, alias lookup, and direct-message rooms.

use super::*;

impl Session {
    pub(super) fn joined_rooms(self, k: K<Vec<Value>>) -> Plan {
        if self.access_token.is_none() {
            return k(self, Vec::new());
        }
        self.fetch(Fetch::get("/joined_rooms"), move |s, r| {
            let rooms = if r.ok {
                r.json.get("joined_rooms").and_then(Value::as_array).cloned().unwrap_or_default()
            } else {
                Vec::new()
            };
            k(s, rooms)
        })
    }

    pub(super) fn cached_room(&self, key: &str) -> Option<Option<String>> {
        let v = self.store.get(key)?;
        let id = v.as_object()?.get("id")?;
        Some(id.as_str().map(str::to_string))
    }

    /// Room id or alias to a joined room id.
    pub(super) fn room_join(self, room: Value, k: K<Option<String>>) -> Plan {
        if self.access_token.is_none() {
            return k(self, None);
        }
        let Some(room) = room.as_str().map(str::to_string) else { return k(self, None) };
        if let Some((token, explicit_hs)) = match_room_id(&room) {
            let home_server = explicit_hs.clone().or_else(|| self.home_server.clone()).unwrap_or_default();
            let cache_key =
                if home_server.is_empty() { format!("!{token}") } else { format!("!{token}:{home_server}") };
            let room_id = if explicit_hs.is_some() || self.cfg.hsreq { cache_key.clone() } else { format!("!{token}") };
            if let Some(cached) = self.cached_room(&cache_key) {
                return k(self, cached);
            }
            let path = format!("/join/{}", quote_path(&room_id));
            return self.fetch(Fetch::post(path, json!({})), move |s, r| {
                if !r.ok {
                    return k(s, None);
                }
                let joined = r.json.get("room_id").filter(|v| has_value(v)).cloned().unwrap_or(json!(room_id));
                s.store.set(&cache_key, json!({"id": joined, "home_server": home_server}), None);
                k(s, joined.as_str().map(str::to_string))
            });
        }
        let Some((name, explicit_hs)) = match_room_alias(&room) else {
            crate::warning!("Ignoring illegally formed room {room} from Matrix server list.");
            return k(self, None);
        };
        let mut home_server = explicit_hs.or_else(|| self.home_server.clone()).filter(|h| !h.is_empty());
        if home_server.is_none()
            && let Some(u) = &self.user_id
        {
            home_server = hs_of(u);
        }
        let Some(home_server) = home_server.filter(|h| !h.is_empty()) else {
            crate::warning!("Could not resolve a homeserver for Matrix room alias {room}.");
            return k(self, None);
        };
        let alias = format!("#{name}:{home_server}");
        if let Some(cached) = self.cached_room(&alias) {
            return k(self, cached);
        }
        let path = format!("/join/{}", quote_path(&alias));
        self.fetch(Fetch::post(path, json!({})), move |s, r| {
            if r.ok {
                let id = r.json.get("room_id").cloned().unwrap_or(Value::Null);
                s.store.set(&alias, json!({"id": id, "home_server": home_server}), None);
                return k(s, id.as_str().map(str::to_string));
            }
            if r.status == 404 || r.json.get("errcode").and_then(Value::as_str) == Some("M_NOT_FOUND") {
                return s.room_create(alias, k);
            }
            crate::warning!(
                "Could not join Matrix room alias {alias} (error={}). If this is a private room, ensure the \
                 user is invited or already joined. Otherwise specify the room_id (!...).",
                r.status
            );
            k(s, None)
        })
    }

    pub(super) fn encryption_state() -> Value {
        json!([{"type": "m.room.encryption", "state_key": "", "content": {"algorithm": "m.megolm.v1.aes-sha2"}}])
    }

    pub(super) fn room_create(self, room: String, k: K<Option<String>>) -> Plan {
        let Some((name, explicit_hs)) = match_room_alias(&room) else { return k(self, None) };
        let mut home_server = explicit_hs.or_else(|| self.home_server.clone()).filter(|h| !h.is_empty());
        if home_server.is_none()
            && let Some(u) = &self.user_id
        {
            home_server = hs_of(u);
        }
        let Some(home_server) = home_server.filter(|h| !h.is_empty()) else { return k(self, None) };
        let room = format!("#{name}:{home_server}");
        let mut payload = json!({
            "room_alias_name": name,
            "name": format!("#{name} - {}", self.msg.app_desc),
            "visibility": "private",
            "preset": "trusted_private_chat",
        });
        let e2ee = self.e2ee_wanted();
        if e2ee {
            payload["initial_state"] = Self::encryption_state();
        }
        self.fetch(Fetch::post("/createRoom", payload), move |s, r| {
            if !r.ok {
                if r.json.get("errcode").and_then(Value::as_str) == Some("M_ROOM_IN_USE") {
                    return s.room_id_lookup(room, k);
                }
                return k(s, None);
            }
            let room_id = r.json.get("room_id").cloned().unwrap_or(Value::Null);
            if let Some(alias) = r.json.get("room_alias").and_then(Value::as_str) {
                s.store.set(alias, json!({"id": room_id, "home_server": home_server}), None);
            }
            let room_id = room_id.as_str().map(str::to_string);
            if e2ee && let Some(rid) = room_id.as_deref().filter(|r| !r.is_empty()) {
                s.store.set(&format!("e2ee_room_enc_{rid}"), json!(true), CACHE_EXPIRY);
            }
            k(s, room_id)
        })
    }

    /// Alias to room id via the room directory.
    pub(super) fn room_id_lookup(self, room: String, k: K<Option<String>>) -> Plan {
        let Some((name, explicit_hs)) = match_room_alias(&room) else { return k(self, None) };
        let mut home_server = explicit_hs.or_else(|| self.home_server.clone()).filter(|h| !h.is_empty());
        if home_server.is_none()
            && let Some(u) = &self.user_id
        {
            home_server = hs_of(u);
        }
        let Some(home_server) = home_server.filter(|h| !h.is_empty()) else { return k(self, None) };
        let path = format!("/directory/room/{}", quote_path(&format!("#{name}:{home_server}")));
        self.fetch(Fetch::get(path), move |s, r| {
            let id = if r.ok { get_str(&r.json, "room_id") } else { None };
            k(s, id)
        })
    }

    /// Find or create the direct-message room with `user`.
    pub(super) fn dm_room(self, user: String, k: K<Option<Value>>) -> Plan {
        let Some((local, explicit_hs)) = match_user(&user) else {
            crate::warning!("Matrix DM: invalid user identifier {user:?}.");
            return k(self, None);
        };
        let Some(home_server) = explicit_hs.or_else(|| self.home_server.clone()).filter(|h| !h.is_empty()) else {
            crate::warning!("Matrix DM: no home server known for user {user:?}.");
            return k(self, None);
        };
        let user_id = format!("@{local}:{home_server}");
        let cache_key = format!("dm_room_{user_id}");
        if let Some(cached) = self.store.get(&cache_key).filter(has_value) {
            return k(self, Some(cached));
        }
        let Some(me) = self.user_id.clone().filter(|u| !u.is_empty()) else {
            return self.dm_create(user_id, Map::new(), k);
        };
        let path = format!("/user/{}/account_data/m.direct", quote_path(&me));
        self.fetch(Fetch::get(path), move |s, r| {
            let mut mdirect = Map::new();
            if let Some(m) = r.object() {
                mdirect = m.clone();
                let rooms = mdirect.get(&user_id).cloned().unwrap_or(json!([]));
                if has_value(&rooms) {
                    let first = match &rooms {
                        Value::Array(a) => a[0].clone(),
                        Value::String(_) => rooms.clone(),
                        Value::Null | Value::Bool(_) | Value::Number(_) | Value::Object(_) => return k(s, None),
                    };
                    s.store.set(&cache_key, first.clone(), CACHE_EXPIRY);
                    return k(s, Some(first));
                }
            }
            s.dm_create(user_id, mdirect, k)
        })
    }

    pub(super) fn dm_create(self, user_id: String, mut mdirect: Map<String, Value>, k: K<Option<Value>>) -> Plan {
        let mut payload = json!({"is_direct": true, "preset": "trusted_private_chat", "invite": [user_id]});
        let e2ee = self.e2ee_wanted();
        if e2ee {
            payload["initial_state"] = Self::encryption_state();
        }
        self.fetch(Fetch::post("/createRoom", payload), move |s, r| {
            if r.object().is_none() {
                crate::warning!("Matrix DM: failed to create room for {user_id}.");
                return k(s, None);
            }
            let Some(room_id) = r.json.get("room_id").filter(|v| has_value(v)).cloned() else { return k(s, None) };
            s.store.set(&format!("dm_room_{user_id}"), room_id.clone(), CACHE_EXPIRY);
            if e2ee && let Some(rid) = room_id.as_str() {
                s.store.set(&format!("e2ee_room_enc_{rid}"), json!(true), CACHE_EXPIRY);
            }
            let Some(me) = s.user_id.clone().filter(|u| !u.is_empty()) else { return k(s, Some(room_id)) };
            let mut list: Vec<Value> = match mdirect.get(&user_id) {
                Some(Value::Array(a)) => a.clone(),
                _ => Vec::new(),
            };
            list.push(room_id.clone());
            mdirect.insert(user_id, Value::Array(list));
            let path = format!("/user/{}/account_data/m.direct", quote_path(&me));
            s.fetch(Fetch::put(path, Value::Object(mdirect)), move |s, _| k(s, Some(room_id)))
        })
    }
}
