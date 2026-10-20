//! MQTT sessions against a scripted in-memory broker: the protocol cost without a network.
//!
//! `cargo bench -p mercurio --bench mqtt`
#![expect(clippy::unwrap_used, reason = "a bench fails loudly on bad setup")]

use std::hint::black_box;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use mercurio::testing::{FakeTransport, ScriptedConn};
use mercurio::{Asset, Message, Target};

/// The control packets in `buf`: `(first byte, body)`.
fn packets(mut buf: &[u8]) -> Vec<(u8, &[u8])> {
    let mut out = Vec::new();
    while let Some(&head) = buf.first() {
        let (mut len, mut shift, mut i) = (0usize, 0, 1);
        loop {
            let b = buf[i];
            len |= usize::from(b & 0x7f) << shift;
            shift += 7;
            i += 1;
            if b & 0x80 == 0 {
                break;
            }
        }
        out.push((head, &buf[i..i + len]));
        buf = &buf[i + len..];
    }
    out
}

/// A broker that accepts the connection and acknowledges QoS 1 and 2 publishes (MQTT 3.1.1).
fn broker() -> ScriptedConn {
    ScriptedConn::bytes(Vec::new(), |buf| {
        let mut reply = Vec::new();
        for (head, body) in packets(buf) {
            match head >> 4 {
                1 => reply.extend_from_slice(&[0x20, 2, 0, 0]),
                3 => {
                    let qos = (head >> 1) & 3;
                    let topic_len = usize::from(u16::from_be_bytes([body[0], body[1]]));
                    let id = &body[2 + topic_len..4 + topic_len];
                    match qos {
                        1 => reply.extend_from_slice(&[0x40, 2, id[0], id[1]]),
                        2 => reply.extend_from_slice(&[0x50, 2, id[0], id[1]]),
                        _ => {}
                    }
                }
                6 => reply.extend_from_slice(&[0x70, 2, body[0], body[1]]),
                _ => {}
            }
        }
        reply
    })
}

fn send(target: &Target, msg: &Message) {
    let fake = FakeTransport::new();
    fake.push_conn(broker());
    let d = target.send(msg, &fake, &Asset::default());
    assert!(d.is_success(), "{d:?}");
}

fn bench(c: &mut Criterion) {
    let topics: Vec<String> = (0..10).map(|i| format!("t/{i}")).collect();
    let qos0 = mercurio::parse(&format!("mqtt://localhost/{}", topics.join(","))).unwrap();
    let qos2 = mercurio::parse(&format!("mqtt://localhost/{}?qos=2", topics.join(","))).unwrap();
    let msg = Message::new("Disk almost full").title("server-1");

    let mut g = c.benchmark_group("mqtt");
    g.bench_function("10_topics_qos0", |b| {
        b.iter_batched(|| (), |()| send(black_box(&qos0), &msg), BatchSize::SmallInput)
    });
    g.bench_function("10_topics_qos2", |b| {
        b.iter_batched(|| (), |()| send(black_box(&qos2), &msg), BatchSize::SmallInput)
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
