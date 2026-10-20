//! XMPP sessions against a scripted in-memory server: the protocol cost without a network.
//!
//! `cargo bench -p mercurio --bench xmpp`
#![expect(clippy::unwrap_used, reason = "a bench fails loudly on bad setup")]

use std::hint::black_box;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use mercurio::testing::{FakeTransport, ScriptedConn};
use mercurio::{Asset, Message, Target};

const HEADER: &str = "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0' from='example.com'>";

/// A server on direct TLS that takes PLAIN, binds a resource, joins rooms and echoes the stream close.
fn server() -> ScriptedConn {
    let mut authed = false;
    ScriptedConn::bytes(Vec::new(), move |buf| {
        let w = String::from_utf8_lossy(buf);
        let mut reply = String::new();
        if w.contains("<stream:stream ") {
            reply.push_str(HEADER);
            reply.push_str(if authed {
                "<stream:features><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/></stream:features>"
            } else {
                "<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>PLAIN</mechanism></mechanisms></stream:features>"
            });
        }
        if w.contains("<auth ") {
            authed = true;
            reply.push_str("<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>");
        }
        if let Some((_, rest)) = w.split_once("<iq type='set' id='") {
            let id = rest.split('\'').next().unwrap();
            reply.push_str(&format!("<iq type='result' id='{id}'/>"));
        }
        if w.contains("</stream:stream>") {
            reply.push_str("</stream:stream>");
        }
        reply.into_bytes()
    })
}

fn send(target: &Target, msg: &Message) {
    let fake = FakeTransport::new();
    fake.push_conn(server());
    let d = target.send(msg, &fake, &Asset::default());
    assert!(d.is_success(), "{d:?}");
}

fn bench(c: &mut Criterion) {
    let base = "xmpps://user:pass@example.com";
    let one = mercurio::parse(&format!("{base}/friend?mode=tls")).unwrap();
    let to: Vec<String> = (0..10).map(|i| format!("friend{i}")).collect();
    let ten = mercurio::parse(&format!("{base}/{}?mode=tls", to.join("/"))).unwrap();
    let msg = Message::new("Disk almost full").title("server-1");

    let mut g = c.benchmark_group("xmpp");
    g.bench_function("1_target", |b| b.iter_batched(|| (), |()| send(black_box(&one), &msg), BatchSize::SmallInput));
    g.bench_function("10_targets", |b| b.iter_batched(|| (), |()| send(black_box(&ten), &msg), BatchSize::SmallInput));
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
