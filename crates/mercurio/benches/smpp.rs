//! SMPP sessions against a scripted in-memory SMSC: the protocol cost without a network.
//!
//! `cargo bench -p mercurio --bench smpp`
#![expect(clippy::unwrap_used, reason = "a bench fails loudly on bad setup")]

use std::hint::black_box;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use mercurio::testing::{FakeTransport, ScriptedConn};
use mercurio::{Asset, Message, Target};

fn word(b: &[u8], i: usize) -> u32 {
    u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}

/// An SMSC that accepts the bind, every submit_sm and the unbind.
fn smsc() -> ScriptedConn {
    ScriptedConn::bytes(Vec::new(), |mut buf| {
        let mut reply = Vec::new();
        while buf.len() >= 16 {
            let (len, command, seq) = (word(buf, 0) as usize, word(buf, 4), word(buf, 12));
            let body: &[u8] = if command == 4 { b"1\0" } else { b"" };
            reply.extend_from_slice(&(16 + body.len() as u32).to_be_bytes());
            reply.extend_from_slice(&(command | 0x8000_0000).to_be_bytes());
            reply.extend_from_slice(&0u32.to_be_bytes());
            reply.extend_from_slice(&seq.to_be_bytes());
            reply.extend_from_slice(body);
            buf = &buf[len..];
        }
        reply
    })
}

fn send(target: &Target, msg: &Message) {
    let fake = FakeTransport::new();
    fake.push_conn(smsc());
    let d = target.send(msg, &fake, &Asset::default());
    assert!(d.is_success(), "{d:?}");
}

fn bench(c: &mut Criterion) {
    let one = mercurio::parse("smpp://user:pass@host/1111111111/2222222222").unwrap();
    let to: Vec<String> = (0..10).map(|i| format!("22222222{i:02}")).collect();
    let ten = mercurio::parse(&format!("smpp://user:pass@host/1111111111/{}", to.join("/"))).unwrap();
    let small = Message::new("Disk almost full");
    let long = Message::new("A longer report that needs concatenated parts. ".repeat(10));

    let mut g = c.benchmark_group("smpp");
    g.bench_function("1_target", |b| b.iter_batched(|| (), |()| send(black_box(&one), &small), BatchSize::SmallInput));
    g.bench_function("10_targets_4_parts", |b| {
        b.iter_batched(|| (), |()| send(black_box(&ten), &long), BatchSize::SmallInput)
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
