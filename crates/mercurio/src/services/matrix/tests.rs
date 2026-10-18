//! Unit tests for the Matrix service: properties the fixtures do not assert (redirect policy, probe credentials, oversized answers, one UUID per raw-token send; the request sequences themselves are fixture cases `login_success`, `discovery_*`, `raw_token_*`), the `?keystore=` directory store and (feature `extra`) reference vectors plus a simulated homeserver whose second device decrypts what mercurio sends and completes a SAS verification.

use serde_json::{Value, json};

use crate::testing::FakeTransport;
use crate::{Asset, Message, Request, Response};

fn send(url: &str, fake: &FakeTransport) -> crate::Delivery {
    send_msg(url, fake, &Message::new("Mercurio Body").title("Mercurio Title"))
}

/// One send, then the target is closed.
fn send_msg(url: &str, fake: &FakeTransport, msg: &Message) -> crate::Delivery {
    let t = crate::parse(url).unwrap_or_else(|e| panic!("{url}: {e}"));
    let d = t.send(msg, fake, &Asset::default());
    t.close(fake, &Asset::default());
    d
}

/// The entries of the only namespace under a `?keystore=` directory.
fn saved_entries(dir: &std::path::Path) -> Value {
    let ns = std::fs::read_dir(dir).unwrap().flatten().find(|e| e.path().is_dir()).unwrap().path();
    serde_json::from_slice(&std::fs::read(ns.join(crate::store::CACHE_FILE)).unwrap()).unwrap()
}

fn json_resp(v: Value) -> Response {
    Response::new(200, serde_json::to_vec(&v).unwrap()).with_header("Content-Type", "application/json")
}

fn paths(fake: &FakeTransport) -> Vec<String> {
    fake.requests().iter().map(|r| format!("{} {}", r.method, r.url)).collect()
}

fn body(r: &Request) -> Value {
    serde_json::from_slice(&r.body).unwrap_or(Value::Null)
}

fn temp_path(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("mercurio-matrix-{tag}-{}", crate::crypto::random_hex(6)))
}

#[test]
fn parse_keeps_secrets_out_of_debug() {
    crate::parse("matrix://u:p@localhost/!a/#b/@c?to=@d").unwrap();
    // Secrets stay out of Debug output.
    let dbg = format!("{:?}", crate::parse("matrix://user:hunter2@localhost/!a").unwrap());
    assert!(!dbg.contains("hunter2"), "{dbg}");
}

#[test]
fn login_success_skips_register_and_logs_out() {
    let fake = FakeTransport::new();
    fake.respond_with(json_resp(json!({"access_token": "tok", "user_id": "@me:localhost", "device_id": "DEV"})));
    let d = send("matrix://me:secret@localhost/!room:localhost", &fake);
    assert!(d.is_success(), "{d:?}");
    let reqs = fake.requests();
    assert_eq!(
        paths(&fake),
        [
            "POST http://localhost/_matrix/client/v3/login",
            "POST http://localhost/_matrix/client/v3/join/%21room%3Alocalhost",
            "PUT http://localhost/_matrix/client/v3/rooms/%21room%3Alocalhost/send/m.room.message/0",
            "POST http://localhost/_matrix/client/v3/logout",
        ]
    );
    assert!(!reqs[0].follow_redirects, "password request must not follow redirects");
    assert_eq!(reqs[1].header_value("authorization"), Some("Bearer tok"));
    // Reuses no device id on a fresh login.
    assert_eq!(body(&reqs[0])["initial_device_display_name"], "Mercurio");
}

#[test]
fn oversized_login_answer_is_rejected() {
    let fake = FakeTransport::new();
    let mut big = json!({"access_token": "tok", "user_id": "@me:localhost"});
    big["pad"] = json!("x".repeat(super::server::MAX_RESPONSE_BYTES));
    fake.respond_with(json_resp(big));
    let d = send("matrix://me:secret@localhost/!room:localhost", &fake);
    assert!(!d.is_success());
    assert!(paths(&fake)[1].ends_with("/register?kind=user"));
}

#[test]
fn discovery_resolves_base_url() {
    let fake = FakeTransport::new();
    fake.respond_with(json_resp(json!({
        "m.homeserver": {"base_url": "https://matrix.example.com/"},
        "m.identity_server": {"base_url": "https://vector.im"},
    })));
    fake.respond_with(json_resp(json!({"versions": ["v1.11"]})));
    fake.respond_with(json_resp(json!({})));
    fake.respond_with(json_resp(json!({"access_token": "tok", "user_id": "@me:example.com", "device_id": "DEV"})));
    let d = send("matrixs://me:secret@example.com/#general?e2ee=no", &fake);
    assert!(!d.is_success(), "join answer has no room_id");
    let p = paths(&fake);
    assert_eq!(p[0], "GET https://example.com/.well-known/matrix/client");
    assert_eq!(p[1], "GET https://matrix.example.com/_matrix/client/versions");
    assert_eq!(p[2], "GET https://vector.im/_matrix/identity/v2");
    assert_eq!(p[3], "POST https://matrix.example.com/_matrix/client/v3/login");
    assert_eq!(p[4], "POST https://matrix.example.com/_matrix/client/v3/join/%23general%3Aexample.com");
    assert_eq!(p[5], "POST https://matrix.example.com/_matrix/client/v3/logout");
    // Probes never carry credentials.
    assert!(fake.requests()[..3].iter().all(|r| r.header_value("authorization").is_none()));
}

#[test]
fn discovery_rejects_unsafe_base_url() {
    for base in ["http://matrix.example.com", "https://user@attacker.example", "https://attacker.example?x=1", "https://e.x/#f"]
    {
        let fake = FakeTransport::new();
        fake.default_response(json_resp(json!({"m.homeserver": {"base_url": base}})));
        let d = send("matrixs://me:secret@example.com/!r?e2ee=no", &fake);
        assert!(!d.is_success(), "{base}");
        // Discovery is retried by the register fallback, then delivery stops.
        assert_eq!(
            paths(&fake),
            ["GET https://example.com/.well-known/matrix/client", "GET https://example.com/.well-known/matrix/client"],
            "{base}"
        );
    }
}

#[test]
fn discovery_identity_failure_stops() {
    let fake = FakeTransport::new();
    fake.respond_with(json_resp(json!({
        "m.homeserver": {"base_url": "https://matrix.example.com"},
        "m.identity_server": {"base_url": "https://vector.im"},
    })));
    fake.respond_with(json_resp(json!({})));
    fake.respond(500, "{}");
    let d = send("matrixs://me:secret@example.com/!r?e2ee=no", &fake);
    assert!(!d.is_success());
    assert_eq!(paths(&fake)[2], "GET https://vector.im/_matrix/identity/v2");
}

#[test]
fn raw_token_uses_uuid_transaction_ids() {
    let fake = FakeTransport::new();
    fake.respond_with(json_resp(json!({"user_id": "@me:localhost"})));
    let d = send("matrix://rawtoken@localhost/!r1:localhost/!r2:localhost", &fake);
    assert!(d.is_success(), "{d:?}");
    let p = paths(&fake);
    assert_eq!(p.len(), 5, "{p:?}");
    assert_eq!(p[0], "GET http://localhost/_matrix/client/v3/account/whoami");
    let txn1 = p[2].rsplit('/').next().unwrap().to_string();
    let txn2 = p[4].rsplit('/').next().unwrap().to_string();
    assert!(crate::parse::is_uuid(&txn1), "{txn1}");
    // A fresh UUID per event. Otherwise the homeserver drops the second one.
    assert!(crate::parse::is_uuid(&txn2), "{txn2}");
    assert_ne!(txn1, txn2);
    assert!(p.iter().all(|x| !x.contains("/logout")), "raw tokens are never logged out");
}

#[test]
fn rate_limit_sleeps_as_requested() {
    let fake = FakeTransport::new();
    fake.respond_with(json_resp(json!({"access_token": "tok", "user_id": "@me:localhost"})));
    fake.respond_with(Response::new(429, br#"{"retry_after_ms": 1500}"#.to_vec()));
    let d = send("matrix://me:secret@localhost/!room:localhost", &fake);
    assert!(d.is_success());
    assert!(fake.sleeps().contains(&std::time::Duration::from_millis(1500)), "{:?}", fake.sleeps());
}

#[test]
fn keystore_file_keeps_the_session() {
    let path = temp_path("keystore");
    let url = format!("matrix://me:secret@localhost/!room:localhost?keystore={}", path.display());
    let fake = FakeTransport::new();
    fake.respond_with(json_resp(json!({"access_token": "tok", "user_id": "@me:localhost", "device_id": "DEV"})));
    assert!(send(&url, &fake).is_success());
    let first = paths(&fake);
    assert!(first[0].ends_with("/login"));
    assert!(!first.iter().any(|p| p.ends_with("/logout")), "persistent stores keep the session");
    assert!(first[2].ends_with("/send/m.room.message/0"));

    let fake = FakeTransport::new();
    assert!(send(&url, &fake).is_success());
    let second = paths(&fake);
    // Token, room cache and transaction counter come from the file.
    assert_eq!(second, ["PUT http://localhost/_matrix/client/v3/rooms/%21room%3Alocalhost/send/m.room.message/1"]);
    assert_eq!(fake.requests()[0].header_value("authorization"), Some("Bearer tok"));
    let ns = saved_entries(&path);
    assert_eq!(ns["transaction_id"]["v"], 2);
    assert_eq!(ns["access_token"]["v"], "tok");
    std::fs::remove_dir_all(&path).ok();
}

#[test]
fn memory_session_outlives_sends_until_close() {
    let fake = FakeTransport::new();
    fake.respond_with(json_resp(json!({"access_token": "tok", "user_id": "@me:localhost", "device_id": "DEV"})));
    let t = crate::parse("matrix://me:secret@localhost/!room:localhost").unwrap();
    let asset = Asset::default();
    assert!(t.send(&Message::new("one"), &fake, &asset).is_success());
    assert!(t.send(&Message::new("two"), &fake, &asset).is_success());
    let p = paths(&fake);
    assert_eq!(p.iter().filter(|p| p.ends_with("/login")).count(), 1, "{p:?}");
    assert!(!p.iter().any(|p| p.ends_with("/logout")));
    assert!(p.last().unwrap().ends_with("/send/m.room.message/1"), "{p:?}");
    assert!(t.close(&fake, &asset).is_some());
    assert!(paths(&fake).last().unwrap().ends_with("/logout"));
    // The session is gone: closing again does nothing.
    assert!(t.close(&fake, &asset).is_none());
}

#[test]
fn split_message_shares_one_session() {
    let fake = FakeTransport::new();
    fake.default_response(json_resp(json!({"access_token": "tok", "user_id": "@me:localhost"})));
    let url = "matrix://me:secret@localhost/!room:localhost?overflow=split";
    let body = "word ".repeat(30000);
    let d = send_msg(url, &fake, &Message::new(body).title("T"));
    assert!(d.is_success());
    let p = paths(&fake);
    let sends: Vec<&String> = p.iter().filter(|p| p.contains("/send/")).collect();
    assert_eq!(sends.len(), 3, "150000 chars split at 65000");
    assert!(sends[2].ends_with("/m.room.message/2"), "{sends:?}");
    assert_eq!(p.iter().filter(|p| p.ends_with("/login")).count(), 1, "{p:?}");
    assert!(p.last().unwrap().ends_with("/logout"));
    assert_eq!(p.iter().filter(|p| p.ends_with("/logout")).count(), 1);
}

/// Runs one raw-token send with a config whose host is empty, so neither the URL nor the whoami answer (`user_id` without `:server`) yields a home server. Parsing never builds such a config; the session must still not invent one.
fn send_without_home_server(rooms: &[&str], users: &[&str], fake: &FakeTransport) -> (crate::Delivery, crate::store::StoreRef) {
    use super::{Config, Mode, Msg, Version};
    let cfg = Config {
        secure: false,
        host: String::new(),
        port: None,
        user: None,
        password: Some(crate::service::Secret::new("rawtoken".to_string())),
        rooms: rooms.iter().map(|r| r.to_string()).collect(),
        users: users.iter().map(|u| u.to_string()).collect(),
        mode: Mode::Off,
        version: Version::V3,
        msgtype: "text".into(),
        include_image: false,
        discovery: false,
        hsreq: true,
        webhook_path: "/webhook".into(),
        e2ee: false,
        autoverify: false,
        t2bot_token: None,
        keystore: None,
    };
    let msg = Msg {
        title: String::new(),
        body: "Mercurio Body".into(),
        kind: crate::message::NotifyType::Info,
        format: crate::NotifyFormat::Text,
        passthrough: true,
        attachments: Vec::new(),
        image_url: None,
        app_id: "Mercurio".into(),
        app_desc: String::new(),
        color: String::new(),
    };
    let store = crate::store::PersistentStore::memory().shared();
    let plan = super::server::plan(std::sync::Arc::new(cfg), msg, store.clone(), crate::store::Memo::disabled());
    (crate::plan::execute(plan, fake, crate::plan::ExecOptions::default()), store)
}

#[test]
fn room_without_home_server_is_cached_as_bare_id() {
    let fake = FakeTransport::new();
    fake.respond_with(json_resp(json!({"user_id": "bot"})));
    fake.respond_with(json_resp(json!({"room_id": "!abc"})));
    let (d, store) = send_without_home_server(&["!abc"], &[], &fake);
    assert!(d.is_success(), "{d:?}");
    let keys = store.keys();
    assert!(keys.iter().all(|k| !k.contains("None") && !k.ends_with(':')), "{keys:?}");
    assert_eq!(store.get("!abc").map(|v| v["id"].clone()), Some(json!("!abc")), "{keys:?}");
    assert!(paths(&fake).iter().all(|p| !p.contains("None") && !p.contains("%3A")), "{:?}", paths(&fake));
}

#[test]
fn dm_without_home_server_is_skipped() {
    let fake = FakeTransport::new();
    fake.respond_with(json_resp(json!({"user_id": "bot"})));
    let (d, store) = send_without_home_server(&[], &["@alice"], &fake);
    // Only whoami was asked: no m.direct lookup, room creation or message.
    assert_eq!(paths(&fake), ["GET http:///_matrix/client/v3/account/whoami"]);
    assert!(!d.is_success());
    assert_eq!(d.outcomes.len(), 1, "{d:?}");
    assert_eq!(d.outcomes[0].target.as_deref(), Some("@alice"));
    assert!(d.outcomes[0].result.is_err());
    assert!(store.keys().iter().all(|k| !k.starts_with("dm_room_")), "{:?}", store.keys());
}

#[cfg(feature = "extra")]
mod e2ee {
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use serde_json::{Map, Value, json};

    use super::super::e2ee::tests::{aes_cbc_decrypt, pb_fields};
    use super::super::e2ee::*;
    use super::super::sas::Sas;
    use super::*;
    use crate::Transport;

    fn b(n: u8) -> [u8; 32] {
        [n; 32]
    }

    // Reference values computed with the same fixed keys.
    #[test]
    fn reference_vectors() {
        let acct = OlmAccount::from_keys(XKey::from_bytes(b(1)), SigningKey::from_seed(b(2)).unwrap());
        assert_eq!(acct.identity_key(), "pOCSkrZRwni5dyxWn1+puxPZBrRqtoyd+dwrRAn4ogk");
        assert_eq!(acct.signing_key(), "gTl3Dqh9F19Wo1Rmw0x+zMuNipG07jeiXfYPW4/Js5Q");
        let dk = acct.device_keys_payload("@a:hs", "DEV");
        assert_eq!(
            dk["signatures"]["@a:hs"]["ed25519:DEV"],
            "4V0J3XnDM5URDZ+6x5Tgic7thfVtJe9f4UCgEMft1UbXWbf0Q6nx/0xMou/7BQRlV+oMfdeo+u7a2MdNPlb3AA"
        );
        let bob_ik = b64enc(&XKey::from_bytes(b(3)).public());
        let bob_otk = b64enc(&XKey::from_bytes(b(4)).public());
        let mut olm = acct.create_outbound_session_with(&bob_ik, &bob_otk, XKey::from_bytes(b(5))).unwrap();
        assert_eq!(
            olm.encrypt(b"hello bob")["body"],
            "AwogrAGyIJ6GNU+4UyN7XeD0+rE8f8v0M6YcAZNpYX/s8QsSIFCmFAmx3dAyXpsWtwDnGel3LAcACxvXeG6QfGU9IEldGiCk4JKStlHCeLl3LFafX6m7E9kGtGq2jJ353CtECfiiCSI/AwogUKYUCbHd0DJemxa3AOcZ6XcsBwALG9d4bpB8ZT0gSV0QACIQchLjOncDw1AZaOJ2bPofasScT26Xh/Dy"
        );
        assert_eq!(
            olm.encrypt(b"again")["body"],
            "AwogrAGyIJ6GNU+4UyN7XeD0+rE8f8v0M6YcAZNpYX/s8QsSIFCmFAmx3dAyXpsWtwDnGel3LAcACxvXeG6QfGU9IEldGiCk4JKStlHCeLl3LFafX6m7E9kGtGq2jJ353CtECfiiCSI/AwogUKYUCbHd0DJemxa3AOcZ6XcsBwALG9d4bpB8ZT0gSV0QASIQZvqYbPyEOofb2Mf9C9qAa64m+bci58HH"
        );

        let mut mg = MegolmSession::from_parts([b(6), b(7), b(8), b(9)], 0, SigningKey::from_seed(b(10)).unwrap(), 0.0);
        assert_eq!(mg.session_id, "Q6cucUQBdi32a2jCbfvfJoKq7J8kdOykYT5CSg+6/Tw");
        assert_eq!(
            mg.session_key(),
            "AgAAAAAGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHCAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCUOnLnFEAXYt9mtowm373yaCquyfJHTspGE+QkoPuv08l20jIJGoeqGp5XiL+qIa8VbW3Yl00R5ggOfumvPILXFFhfwlx6UeW5FW72YOF/VnyI+Z+UOgi24bvRJo4LsSDw"
        );
        assert_eq!(
            mg.encrypt_bytes(br#"{"a": 1}"#),
            "AwgAEhDp82X54+R44+DeN6YRBBCTMP+PbKBydA0FZik11dUdfiSNFPRu3nWC5gmK+4XxVdC4jJ7cUd9ckc5G/Fa4YN7fvp9zVShGokKFXjTAjtUCS8+tSlf/O/wK"
        );
        assert_eq!(
            mg.encrypt_bytes(r#"{"type": "m.room.message", "content": {"body": "é"}}"#.as_bytes()),
            "AwgBEkDXijk3wWoqsDAlj787K0bWwqnBJrXJcgY+1A7v9gxViuga7RSIt3/G6WmwfMM2mZSY9lqRwK+AwjZTxrN4fVXMKLJuYfiDcZ+3R4eqHLZdp7W+uMLWthdzowGf9KEM+bZ4EDc9ZatGDOIgAKVk/27qfHpJI8/L/GNvepRrSc8/aiVLd579coYD"
        );
        assert_eq!(
            mg.session_key(),
            "AgAAAAIGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHCAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAiVeWylJd37QHvN/UQEVrdpwcNP6nKgvS9sw1up9hEsvEOnLnFEAXYt9mtowm373yaCquyfJHTspGE+QkoPuv08uTwyLTEw2aZEz2xPcjX9Zd1qTG4NAcyHB9nkqWuwEV0ckrDKCMz29lDdunmqbAAvjBkqdLhrdSOlhJPGycA8BA"
        );

        let start = json!({
            "from_device": "ELEMENT", "transaction_id": "tx1", "method": "m.sas.v1",
            "key_agreement_protocols": ["curve25519-hkdf-sha256"], "hashes": ["sha256"],
            "message_authentication_codes": ["hkdf-hmac-sha256.v2"],
            "short_authentication_string": ["decimal", "emoji"],
        });
        let mut sas = Sas::with_key("@u:h", "MERCURIO", "@u:h", "ELEMENT", &start, XKey::from_bytes(b(11))).unwrap();
        assert_eq!(sas.accept_content().unwrap()["commitment"], "jwH22AkRAWeZVOe00DbMGtYPkAQhrKBDA2gatwl+cyo");
        let peer = b64enc(&XKey::from_bytes(b(12)).public());
        assert_eq!(peer, "l8OxC01sEzp46l3MHPZCHT+Brjex9ijOFMpvzncw8zM");
        sas.receive_key(&json!(peer)).unwrap();
        assert_eq!(sas.decimal_sas().unwrap(), (3814, 6308, 6256));
        let mac = sas.mac_content(&acct.signing_key()).unwrap();
        assert_eq!(mac["mac"]["ed25519:MERCURIO"], "4T5bJKEah39PF2jzPsITj20qR6F3wcxQz25xCeDemB0");
        assert_eq!(mac["keys"], "+HUoq05Ys2tdGhxnxgg/VAMOcIbrpgD8fcsmtBaRtJE");
    }

    const ME: &str = "@me:hs.test";
    const BOB: &str = "@bob:hs.test";

    struct Peer {
        bob: OlmAccount,
        bob_otk: XKey,
        element: OlmAccount,
        element_sas_key: XKey,
    }

    #[derive(Default)]
    struct World {
        uploaded_device_keys: Option<Value>,
        room_key: Option<(String, [[u8; 32]; 4])>,
        decrypted: Vec<Value>,
        media: BTreeMap<String, Vec<u8>>,
        sas_step: u32,
        sas_our_key: Option<String>,
        sas_accept: Option<Value>,
        sas_peer_mac_ok: bool,
        sas_done_seen: bool,
        sync_calls: u32,
        claims: u32,
    }

    struct Homeserver {
        peer: Peer,
        world: Mutex<World>,
        autoverify: bool,
    }

    fn start_content() -> Value {
        json!({
            "from_device": "ELEMENT", "transaction_id": "sas-1", "method": "m.sas.v1",
            "key_agreement_protocols": ["curve25519-hkdf-sha256"], "hashes": ["sha256"],
            "message_authentication_codes": ["hkdf-hmac-sha256.v2"],
            "short_authentication_string": ["decimal"],
        })
    }

    fn mac_for(shared: &[u8; 32], value: &str, key_id: &str, sender: (&str, &str), receiver: (&str, &str)) -> String {
        let info =
            format!("MATRIX_KEY_VERIFICATION_MAC{}{}{}{}sas-1{key_id}", sender.0, sender.1, receiver.0, receiver.1);
        b64enc(&hmac_sha256(&hkdf_sha256(shared, 32, None, info.as_bytes()), value.as_bytes()))
    }

    impl Homeserver {
        fn new(autoverify: bool) -> Self {
            Homeserver {
                peer: Peer {
                    bob: OlmAccount::new(),
                    bob_otk: XKey::generate(),
                    element: OlmAccount::new(),
                    element_sas_key: XKey::generate(),
                },
                world: Mutex::new(World::default()),
                autoverify,
            }
        }

        fn ok(v: Value) -> crate::Result<Response> {
            Ok(json_resp(v))
        }

        /// Bob opens the Olm pre-key message and keeps the Megolm session key.
        fn bob_receives(&self, w: &mut World, msg: &Value) {
            let bob_ik = self.peer.bob.identity_key();
            let ct = &msg["messages"][BOB]["BOBDEV"]["ciphertext"][&bob_ik];
            assert_eq!(ct["type"], 0);
            let raw = b64dec(ct["body"].as_str().unwrap()).unwrap();
            let outer = pb_fields(&raw[1..]);
            let base_key = outer[&2].0.clone();
            let alice_ik = outer[&3].0.clone();
            assert_eq!(b64enc(&alice_ik), msg["messages"][BOB]["BOBDEV"]["sender_key"].as_str().unwrap());
            let dh1 = self.peer.bob_otk.exchange(&alice_ik).unwrap();
            let dh2 = self.peer.bob.identity_private().exchange(&base_key).unwrap();
            let dh3 = self.peer.bob_otk.exchange(&base_key).unwrap();
            let keys = hkdf_sha256(&[dh1, dh2, dh3].concat(), 64, None, b"OLM_ROOT");
            let msg_key = hmac_sha256(&keys[32..], b"\x01");
            let k = hkdf_sha256(&msg_key, 80, Some(&[0u8; 32]), b"OLM_KEYS");
            let inner = &outer[&4].0;
            let (body, mac) = inner.split_at(inner.len() - 8);
            assert_eq!(&hmac_sha256(&k[32..64], body)[..8], mac, "Olm MAC");
            let f = pb_fields(&body[1..]);
            let plain: Value = serde_json::from_slice(&aes_cbc_decrypt(&k[..32], &k[64..80], &f[&4].0)).unwrap();
            assert_eq!(plain["type"], "m.room_key");
            assert_eq!(plain["recipient"], BOB);
            assert_eq!(plain["recipient_keys"]["ed25519"], self.peer.bob.signing_key());
            let key = b64dec(plain["content"]["session_key"].as_str().unwrap()).unwrap();
            let sid = plain["content"]["session_id"].as_str().unwrap().to_string();
            assert!(verify_ed25519(&sid, &key[..165], &b64enc(&key[165..])), "session key signature");
            let mut ratchet = [[0u8; 32]; 4];
            for (i, r) in ratchet.iter_mut().enumerate() {
                r.copy_from_slice(&key[5 + 32 * i..5 + 32 * (i + 1)]);
            }
            w.room_key = Some((sid, ratchet));
        }

        /// Decrypt a Megolm room event with the shared key (message index 0, 1, ...).
        fn bob_reads(&self, w: &mut World, event: &Value) {
            let (sid, ratchet) = w.room_key.clone().expect("room key shared before the first event");
            assert_eq!(event["session_id"], json!(sid));
            let raw = b64dec(event["ciphertext"].as_str().unwrap()).unwrap();
            let (signed, sig) = raw.split_at(raw.len() - 64);
            assert!(verify_ed25519(&sid, signed, &b64enc(sig)), "Megolm signature");
            let (body, _mac) = signed.split_at(signed.len() - 8);
            let f = pb_fields(&body[1..]);
            let index = f[&1].1 as u32;
            let mut inbound = MegolmSession::from_parts(ratchet, 0, SigningKey::generate(), 0.0);
            for _ in 0..index {
                inbound.encrypt_bytes(b"");
            }
            let keys = hkdf_sha256(&inbound_ratchet(&inbound), 80, None, b"MEGOLM_KEYS");
            let plain = aes_cbc_decrypt(&keys[..32], &keys[64..80], &f[&2].0);
            w.decrypted.push(serde_json::from_slice(&plain).unwrap());
        }
    }

    /// The ratchet value R_i of a session (via its exported key).
    fn inbound_ratchet(s: &MegolmSession) -> Vec<u8> {
        let key = b64dec(&s.session_key()).unwrap();
        key[5..133].to_vec()
    }

    impl Transport for Homeserver {
        fn http(&self, req: &Request) -> crate::Result<Response> {
            let mut w = self.world.lock().unwrap();
            let url = req.url.clone();
            let path =
                url.split("/_matrix/").nth(1).map(|p| p.split('?').next().unwrap().to_string()).unwrap_or_default();
            let path = crate::url::unquote(&path);
            let body: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
            if url.contains("/.well-known/") {
                return Ok(Response::new(404, b"{}".to_vec()));
            }
            match (req.method.as_str(), path.as_str()) {
                ("POST", "client/v3/login") => {
                    Self::ok(json!({"access_token": "tok", "user_id": ME, "device_id": "MERCURIO"}))
                }
                ("POST", "client/v3/keys/upload") => {
                    assert!(
                        verify_device_keys(&body["device_keys"], ME, "MERCURIO"),
                        "our device keys are self-signed"
                    );
                    let (_, fb) = body["fallback_keys"].as_object().unwrap().iter().next().unwrap();
                    let ed = body["device_keys"]["keys"]["ed25519:MERCURIO"].as_str().unwrap();
                    assert!(verify_signed_otk(fb, ME, "MERCURIO", ed), "fallback key is signed");
                    w.uploaded_device_keys = Some(body["device_keys"].clone());
                    Self::ok(json!({"one_time_key_counts": {}}))
                }
                ("POST", p) if p.starts_with("client/v3/join/") => Self::ok(json!({"room_id": "!room:hs.test"})),
                ("GET", "client/v3/rooms/!room:hs.test/state/m.room.encryption") => {
                    Self::ok(json!({"algorithm": "m.megolm.v1.aes-sha2"}))
                }
                ("GET", "client/v3/rooms/!room:hs.test/joined_members") => {
                    Self::ok(json!({"joined": {ME: {}, BOB: {}}}))
                }
                ("POST", "client/v3/keys/query") => {
                    let mut dk = Map::new();
                    if body["device_keys"].get(BOB).is_some() {
                        dk.insert(BOB.into(), json!({"BOBDEV": self.peer.bob.device_keys_payload(BOB, "BOBDEV")}));
                    }
                    if body["device_keys"].get(ME).is_some() {
                        let mut mine = Map::new();
                        mine.insert("ELEMENT".into(), self.peer.element.device_keys_payload(ME, "ELEMENT"));
                        if let Some(k) = &w.uploaded_device_keys {
                            mine.insert("MERCURIO".into(), k.clone());
                        }
                        dk.insert(ME.into(), Value::Object(mine));
                    }
                    Self::ok(json!({"device_keys": dk}))
                }
                ("POST", "client/v3/keys/claim") => {
                    w.claims += 1;
                    // Our own device must not be claimed for; ELEMENT has no OTK left.
                    assert!(body["one_time_keys"][ME].get("MERCURIO").is_none());
                    let otk = json!({"key": b64enc(&self.peer.bob_otk.public())});
                    let sig = self.peer.bob.sign(canonical_json(&otk).as_bytes());
                    let mut otk = otk;
                    otk["signatures"] = json!({BOB: {"ed25519:BOBDEV": sig}});
                    Self::ok(json!({"one_time_keys": {BOB: {"BOBDEV": {"signed_curve25519:AAAAAQ": otk}}}}))
                }
                ("PUT", p) if p.starts_with("client/v3/sendToDevice/m.room.encrypted/") => {
                    assert!(body["messages"][ME].as_object().is_some_and(|m| m.is_empty()), "own devices skipped");
                    self.bob_receives(&mut w, &body);
                    Self::ok(json!({}))
                }
                ("PUT", p) if p.starts_with("client/v3/rooms/!room:hs.test/send/m.room.encrypted/") => {
                    assert_eq!(body["algorithm"], "m.megolm.v1.aes-sha2");
                    assert_eq!(body["device_id"], "MERCURIO");
                    self.bob_reads(&mut w, &body);
                    Self::ok(json!({"event_id": "$e"}))
                }
                ("POST", "media/v3/upload") => {
                    let id = format!("mxc://hs.test/{}", w.media.len());
                    w.media.insert(id.clone(), req.body.clone());
                    Self::ok(json!({"content_uri": id}))
                }
                ("GET", "client/v3/sync") => {
                    w.sync_calls += 1;
                    assert!(self.autoverify, "sync only with autoverify");
                    let ev = |t: &str, c: Value| json!({"type": t, "sender": ME, "content": c});
                    let events = match w.sas_step {
                        0 => vec![ev(
                            "m.key.verification.request",
                            json!({"from_device": "ELEMENT", "transaction_id": "sas-1", "methods": ["m.sas.v1"],
                                   "timestamp": crate::crypto::unix_time_ms() as i64}),
                        )],
                        2 => vec![ev("m.key.verification.start", start_content())],
                        4 => vec![ev(
                            "m.key.verification.key",
                            json!({"transaction_id": "sas-1", "key": b64enc(&self.peer.element_sas_key.public())}),
                        )],
                        6 => {
                            let ours = w.sas_our_key.clone().unwrap();
                            let shared = self.peer.element_sas_key.exchange(&b64dec(&ours).unwrap()).unwrap();
                            let kid = "ed25519:ELEMENT";
                            let mac = mac_for(
                                &shared,
                                &self.peer.element.signing_key(),
                                kid,
                                (ME, "ELEMENT"),
                                (ME, "MERCURIO"),
                            );
                            let keys = mac_for(&shared, kid, "KEY_IDS", (ME, "ELEMENT"), (ME, "MERCURIO"));
                            vec![
                                ev(
                                    "m.key.verification.mac",
                                    json!({"transaction_id": "sas-1", "mac": {kid: mac}, "keys": keys}),
                                ),
                                ev("m.key.verification.done", json!({"transaction_id": "sas-1"})),
                            ]
                        }
                        _ => vec![],
                    };
                    Self::ok(json!({"next_batch": format!("b{}", w.sync_calls), "to_device": {"events": events}}))
                }
                ("PUT", p) if p.starts_with("client/v3/sendToDevice/m.key.verification.") => {
                    let kind =
                        p.trim_start_matches("client/v3/sendToDevice/m.key.verification.").split('/').next().unwrap();
                    let c = &body["messages"][ME]["ELEMENT"];
                    assert_eq!(c["transaction_id"], "sas-1");
                    match kind {
                        "ready" => {
                            assert_eq!(w.sas_step, 0);
                            assert_eq!(c["from_device"], "MERCURIO");
                            w.sas_step = 2;
                        }
                        "accept" => {
                            assert_eq!(w.sas_step, 2);
                            w.sas_accept = Some(c.clone());
                            w.sas_step = 4;
                        }
                        "key" => {
                            assert_eq!(w.sas_step, 4);
                            let ours = c["key"].as_str().unwrap().to_string();
                            // The accept commitment binds our key to the start content.
                            let mut data = ours.as_bytes().to_vec();
                            data.extend_from_slice(canonical_json(&start_content()).as_bytes());
                            assert_eq!(w.sas_accept.as_ref().unwrap()["commitment"], json!(b64enc(&sha256(&data))));
                            w.sas_our_key = Some(ours);
                        }
                        "mac" => {
                            let ours = w.sas_our_key.clone().unwrap();
                            let shared = self.peer.element_sas_key.exchange(&b64dec(&ours).unwrap()).unwrap();
                            let our_ed = w.uploaded_device_keys.as_ref().unwrap()["keys"]["ed25519:MERCURIO"]
                                .as_str()
                                .unwrap()
                                .to_string();
                            let kid = "ed25519:MERCURIO";
                            let want = mac_for(&shared, &our_ed, kid, (ME, "MERCURIO"), (ME, "ELEMENT"));
                            w.sas_peer_mac_ok = c["mac"][kid] == json!(want)
                                && c["keys"]
                                    == json!(mac_for(&shared, kid, "KEY_IDS", (ME, "MERCURIO"), (ME, "ELEMENT")));
                            w.sas_step = 6;
                        }
                        "done" => w.sas_done_seen = true,
                        "cancel" => panic!("unexpected cancel: {c}"),
                        other => panic!("unexpected {other}"),
                    }
                    Self::ok(json!({}))
                }
                ("POST", "client/v3/logout") => Self::ok(json!({})),
                other => panic!("unexpected request {other:?}"),
            }
        }

        fn sleep(&self, _: std::time::Duration) {}
    }

    #[test]
    fn bob_decrypts_message_and_attachment() {
        let hs = Homeserver::new(false);
        let png = Attachment::new("a.png", "image/png", vec![1, 2, 3, 4, 5]);
        let msg = Message::new("Secret body").title("T").format(crate::NotifyFormat::Html).attach(png);
        let t = crate::parse("matrixs://me:pw@hs.test/!room:hs.test").unwrap();
        let d = t.send(&msg, &hs, &Asset::default());
        assert!(d.is_success(), "{d:?}");
        let w = hs.world.lock().unwrap();
        assert_eq!(w.decrypted.len(), 2);
        let m = &w.decrypted[0];
        assert_eq!(m["type"], "m.room.message");
        assert_eq!(m["room_id"], "!room:hs.test");
        assert_eq!(m["content"]["body"], "# T\r\nSecret body");
        assert_eq!(m["content"]["formatted_body"], "<h1>T</h1><br/>Secret body");
        let a = &w.decrypted[1]["content"];
        assert_eq!(a["msgtype"], "m.image");
        assert_eq!(a["info"]["size"], 5);
        let file = &a["file"];
        let data = &w.media[file["url"].as_str().unwrap()];
        assert_eq!(file["hashes"]["sha256"], json!(b64enc(&sha256(data))));
        let key: [u8; 32] = b64dec(file["key"]["k"].as_str().unwrap()).unwrap().try_into().unwrap();
        let iv: [u8; 16] = b64dec(file["iv"].as_str().unwrap()).unwrap().try_into().unwrap();
        assert_eq!(aes_ctr(&key, &iv, data), vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn autoverify_completes_sas_and_persists_trust() {
        let path = temp_path("sas");
        let url = format!("matrixs://me:pw@hs.test/!room:hs.test?autoverify=yes&keystore={}", path.display());
        let hs = Homeserver::new(true);
        let t = crate::parse(&url).unwrap();
        let d = t.send(&Message::new("hello").title("T"), &hs, &Asset::default());
        assert!(d.is_success(), "{d:?}");
        {
            let w = hs.world.lock().unwrap();
            assert!(w.sas_peer_mac_ok, "our SAS MAC matches the peer's derivation");
            assert!(w.sas_done_seen);
            assert_eq!(w.decrypted.len(), 1);
            assert_eq!(w.claims, 1);
        }
        let ns = saved_entries(&path);
        assert_eq!(ns["e2ee_verified_binding"]["v"], ns["e2ee_device_binding"]["v"]);
        assert_eq!(ns["e2ee_keys_uploaded"]["v"], true);

        // Second run: same identity, no key upload, no sync, the Megolm session is reused (no new claim / room key share).
        let syncs = hs.world.lock().unwrap().sync_calls;
        let d = t.send(&Message::new("again"), &hs, &Asset::default());
        assert!(d.is_success(), "{d:?}");
        let w = hs.world.lock().unwrap();
        assert_eq!(w.sync_calls, syncs);
        assert_eq!(w.claims, 1);
        assert_eq!(w.decrypted.len(), 2);
        assert_eq!(w.decrypted[1]["content"]["body"], "again");
        drop(w);
        std::fs::remove_dir_all(&path).ok();
    }

    use crate::Attachment;

    // Flow hardening (FakeTransport)

    const E2EE_URL: &str = "matrixs://me:pw@hs.test/!room:hs.test?discovery=no";

    /// Login, then every request gets `200 {}` unless a rule says otherwise.
    fn e2ee_fake() -> FakeTransport {
        let fake = FakeTransport::new();
        fake.on_url("/login", json_resp(json!({"access_token": "tok", "user_id": ME, "device_id": "MERCURIO"})));
        fake.on_url("/join/", json_resp(json!({"room_id": "!room:hs.test"})));
        fake
    }

    fn count(fake: &FakeTransport, needle: &str) -> usize {
        paths(fake).iter().filter(|p| p.contains(needle)).count()
    }

    fn only_class(d: &crate::Delivery) -> crate::ErrorClass {
        let errors: Vec<&crate::Error> = d.errors().collect();
        assert_eq!(errors.len(), 1, "{d:?}");
        errors[0].class()
    }

    #[test]
    fn encryption_state_error_fails_the_room_and_is_not_cached() {
        let fake = e2ee_fake();
        fake.on_url("/state/m.room.encryption", Response::new(502, b"{}".to_vec()));
        let t = crate::parse(E2EE_URL).unwrap();
        let d = t.send(&Message::new("hi"), &fake, &Asset::default());
        assert!(!d.is_success());
        assert_eq!(only_class(&d), crate::ErrorClass::Transient, "a 5xx stays retryable");
        assert_eq!(count(&fake, "/send/"), 0, "nothing sent, least of all plaintext: {:?}", paths(&fake));
        // Not cached: the next send asks again.
        let d = t.send(&Message::new("hi"), &fake, &Asset::default());
        assert!(!d.is_success());
        assert_eq!(count(&fake, "/state/m.room.encryption"), 2);
        assert_eq!(count(&fake, "/send/"), 0);
    }

    #[test]
    fn encryption_state_timeout_fails_the_room() {
        let fake = FakeTransport::new();
        fake.respond_with(json_resp(json!({"access_token": "tok", "user_id": ME, "device_id": "MERCURIO"})));
        fake.respond_with(json_resp(json!({}))); // keys/upload
        fake.respond_with(json_resp(json!({"room_id": "!room:hs.test"}))); // join
        fake.fail(crate::Error::transport("timed out connecting"));
        let d = send(E2EE_URL, &fake);
        assert!(!d.is_success());
        assert_eq!(only_class(&d), crate::ErrorClass::Transient);
        assert_eq!(count(&fake, "/send/"), 0, "{:?}", paths(&fake));
    }

    #[test]
    fn empty_encryption_state_counts_as_encrypted() {
        // A 200 with empty (e.g. redacted) content is still an encrypted room.
        let fake = e2ee_fake();
        let d = send(E2EE_URL, &fake);
        assert!(d.is_success(), "{d:?}");
        assert_eq!(count(&fake, "/send/m.room.encrypted/"), 1);
        assert_eq!(count(&fake, "/send/m.room.message/"), 0);
    }

    #[test]
    fn not_found_means_unencrypted_and_is_cached() {
        let fake = e2ee_fake();
        fake.on_url("/state/m.room.encryption", Response::new(404, br#"{"errcode":"M_NOT_FOUND"}"#.to_vec()));
        let t = crate::parse(E2EE_URL).unwrap();
        assert!(t.send(&Message::new("one"), &fake, &Asset::default()).is_success());
        assert!(t.send(&Message::new("two"), &fake, &Asset::default()).is_success());
        assert_eq!(count(&fake, "/send/m.room.message/"), 2);
        assert_eq!(count(&fake, "/state/m.room.encryption"), 1, "{:?}", paths(&fake));
    }

    #[test]
    fn bare_404_is_not_a_definitive_answer() {
        let fake = e2ee_fake();
        fake.on_url("/state/m.room.encryption", Response::new(404, b"<html>proxy</html>".to_vec()));
        let d = send(E2EE_URL, &fake);
        assert!(!d.is_success());
        assert_eq!(count(&fake, "/send/"), 0, "{:?}", paths(&fake));
    }

    #[test]
    fn encrypted_room_never_gets_plaintext_when_setup_fails() {
        let fake = e2ee_fake();
        fake.on_url("/keys/upload", Response::new(503, b"{}".to_vec()));
        fake.on_url("/state/m.room.encryption", json_resp(json!({"algorithm": MEGOLM_ALGORITHM})));
        let d = send(E2EE_URL, &fake);
        assert!(!d.is_success());
        assert_eq!(only_class(&d), crate::ErrorClass::Transient, "the setup failure's class is kept");
        assert_eq!(count(&fake, "/send/"), 0, "{:?}", paths(&fake));
    }

    #[test]
    fn unencrypted_room_still_works_when_setup_fails() {
        let fake = e2ee_fake();
        fake.on_url("/keys/upload", Response::new(503, b"{}".to_vec()));
        fake.on_url("/state/m.room.encryption", Response::new(404, br#"{"errcode":"M_NOT_FOUND"}"#.to_vec()));
        let d = send(E2EE_URL, &fake);
        assert!(d.is_success(), "{d:?}");
        assert_eq!(count(&fake, "/send/m.room.message/"), 1);
    }

    // Room membership: a scripted encrypted room

    /// One member device of the scripted room.
    struct Dev {
        user: &'static str,
        id: &'static str,
        acct: OlmAccount,
    }

    impl Dev {
        fn new(user: &'static str, id: &'static str) -> Self {
            Dev { user, id, acct: OlmAccount::new() }
        }
    }

    /// An encrypted room whose joined members are exactly `devs` (plus us).
    fn room_fake(devs: &[&Dev]) -> FakeTransport {
        let fake = e2ee_fake();
        fake.on_url("/state/m.room.encryption", json_resp(json!({"algorithm": MEGOLM_ALGORITHM})));
        let mut joined = Map::new();
        joined.insert(ME.into(), json!({}));
        let mut keys: Map<String, Value> = Map::new();
        let mut otks: Map<String, Value> = Map::new();
        for d in devs {
            joined.insert(d.user.into(), json!({}));
            let user_keys = keys.entry(d.user).or_insert_with(|| json!({}));
            user_keys[d.id] = d.acct.device_keys_payload(d.user, d.id);
            let mut otk = json!({"key": b64enc(&XKey::generate().public())});
            let sig = d.acct.sign(canonical_json(&otk).as_bytes());
            otk["signatures"] = json!({d.user: {format!("ed25519:{}", d.id): sig}});
            let user_otks = otks.entry(d.user).or_insert_with(|| json!({}));
            user_otks[d.id] = json!({"signed_curve25519:AAAAAQ": otk});
        }
        fake.on_url("/joined_members", json_resp(json!({"joined": joined})));
        fake.on_url("/keys/query", json_resp(json!({"device_keys": keys})));
        fake.on_url("/keys/claim", json_resp(json!({"one_time_keys": otks})));
        fake
    }

    fn room_url(dir: &std::path::Path) -> String {
        format!("{E2EE_URL}&keystore={}", dir.display())
    }

    /// One send through a fresh target (state comes from the keystore).
    fn room_send(dir: &std::path::Path, fake: &FakeTransport) {
        let t = crate::parse(&room_url(dir)).unwrap();
        let d = t.send(&Message::new("hi"), fake, &Asset::default());
        assert!(d.is_success(), "{d:?}: {:?}", paths(fake));
    }

    /// Age out the cached member list, as [`MEMBERS_TTL`] would.
    fn expire_members(dir: &std::path::Path) {
        let ns = std::fs::read_dir(dir).unwrap().flatten().find(|e| e.path().is_dir()).unwrap().path();
        let file = ns.join(crate::store::CACHE_FILE);
        let mut v: Value = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
        for (k, e) in v.as_object_mut().unwrap() {
            if k.starts_with("e2ee_members_") {
                e["x"] = json!(1.0);
            }
        }
        std::fs::write(&file, serde_json::to_vec(&v).unwrap()).unwrap();
    }

    fn req_bodies(fake: &FakeTransport, needle: &str) -> Vec<Value> {
        fake.requests().iter().filter(|r| r.url.contains(needle)).map(body).collect()
    }

    /// `user/device` pairs a request body addresses under `field`.
    fn addressed(v: &Value, field: &str) -> Vec<String> {
        let mut out = Vec::new();
        for (u, devs) in v[field].as_object().into_iter().flatten() {
            for d in devs.as_object().into_iter().flatten().map(|(d, _)| d) {
                out.push(format!("{u}/{d}"));
            }
        }
        out
    }

    fn sent_session(fake: &FakeTransport) -> String {
        let sends = req_bodies(fake, "/send/m.room.encrypted/");
        assert_eq!(sends.len(), 1, "{:?}", paths(fake));
        sends[0]["session_id"].as_str().unwrap().to_string()
    }

    #[test]
    fn new_device_gets_the_current_session_key() {
        let dir = temp_path("join");
        let bob = Dev::new(BOB, "BOBDEV");
        let carol = Dev::new("@carol:hs.test", "CAROLDEV");
        let first = room_fake(&[&bob]);
        room_send(&dir, &first);
        assert_eq!(addressed(&req_bodies(&first, "/sendToDevice/")[0], "messages"), [format!("{BOB}/BOBDEV")]);

        // Within the TTL the member list is reused: no queries, no claims.
        let cached = room_fake(&[&bob, &carol]);
        room_send(&dir, &cached);
        assert_eq!(count(&cached, "/joined_members") + count(&cached, "/keys/"), 0, "{:?}", paths(&cached));
        assert_eq!(sent_session(&cached), sent_session(&first));

        // Carol joined: only her device is claimed for and gets the key.
        expire_members(&dir);
        let second = room_fake(&[&bob, &carol]);
        room_send(&dir, &second);
        assert_eq!(addressed(&req_bodies(&second, "/keys/claim")[0], "one_time_keys"), ["@carol:hs.test/CAROLDEV"]);
        assert_eq!(addressed(&req_bodies(&second, "/sendToDevice/")[0], "messages"), ["@carol:hs.test/CAROLDEV"]);
        assert_eq!(sent_session(&second), sent_session(&first), "no rotation on join");

        // Nothing changed: nothing to share.
        expire_members(&dir);
        let third = room_fake(&[&bob, &carol]);
        room_send(&dir, &third);
        assert_eq!(count(&third, "/keys/claim") + count(&third, "/sendToDevice/"), 0, "{:?}", paths(&third));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn leaving_member_rotates_the_session() {
        let dir = temp_path("leave");
        let bob = Dev::new(BOB, "BOBDEV");
        let carol = Dev::new("@carol:hs.test", "CAROLDEV");
        let first = room_fake(&[&bob, &carol]);
        room_send(&dir, &first);
        let old = sent_session(&first);

        expire_members(&dir);
        let second = room_fake(&[&bob]);
        room_send(&dir, &second);
        let new = sent_session(&second);
        assert_ne!(new, old, "carol left: new Megolm session");
        // The new key goes to the remaining member only.
        assert_eq!(addressed(&req_bodies(&second, "/sendToDevice/")[0], "messages"), [format!("{BOB}/BOBDEV")]);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn removed_device_rotates_the_session() {
        let dir = temp_path("devgone");
        let bob = Dev::new(BOB, "BOBDEV");
        let bob2 = Dev::new(BOB, "BOBPHONE");
        let first = room_fake(&[&bob, &bob2]);
        room_send(&dir, &first);
        let old = sent_session(&first);
        expire_members(&dir);
        let second = room_fake(&[&bob]);
        room_send(&dir, &second);
        assert_ne!(sent_session(&second), old);
        std::fs::remove_dir_all(&dir).ok();
    }

    // Trust on first use

    #[test]
    fn device_keys_are_pinned_on_first_sight() {
        let dir = temp_path("pin");
        let bob = Dev::new(BOB, "BOBDEV");
        room_send(&dir, &room_fake(&[&bob]));
        let pin = &saved_entries(&dir)[format!("e2ee_pin_{BOB}")];
        assert_eq!(pin["v"]["BOBDEV"]["ed25519"], json!(bob.acct.signing_key()));
        assert_eq!(pin["v"]["BOBDEV"]["curve25519"], json!(bob.acct.identity_key()));
        assert!(pin["x"].is_null(), "pins do not expire");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn device_with_changed_keys_gets_no_room_key() {
        let dir = temp_path("pinchange");
        let bob = Dev::new(BOB, "BOBDEV");
        let first = room_fake(&[&bob]);
        room_send(&dir, &first);
        let old = sent_session(&first);

        // Same device id, new (validly self-signed) keys: refused.
        expire_members(&dir);
        let imposter = Dev::new(BOB, "BOBDEV");
        let second = room_fake(&[&imposter]);
        room_send(&dir, &second);
        assert_eq!(count(&second, "/keys/claim") + count(&second, "/sendToDevice/"), 0, "{:?}", paths(&second));
        assert_ne!(sent_session(&second), old, "the pinned holder is gone: rotated");
        let pin = &saved_entries(&dir)[format!("e2ee_pin_{BOB}")];
        assert_eq!(pin["v"]["BOBDEV"]["ed25519"], json!(bob.acct.signing_key()), "the first keys stay pinned");

        // The genuine device is accepted again and gets the new session.
        expire_members(&dir);
        let third = room_fake(&[&bob]);
        room_send(&dir, &third);
        assert_eq!(addressed(&req_bodies(&third, "/sendToDevice/")[0], "messages"), [format!("{BOB}/BOBDEV")]);
        std::fs::remove_dir_all(&dir).ok();
    }
}
