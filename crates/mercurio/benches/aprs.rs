//! APRS-IS sessions against a scripted in-memory server: the protocol cost without a network.
//!
//! `cargo bench -p mercurio --bench aprs`
#![expect(clippy::unwrap_used, reason = "a bench fails loudly on bad setup")]

use std::hint::black_box;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use mercurio::testing::{FakeTransport, ScriptedConn};
use mercurio::{Asset, Message, Target};

/// A server that verifies the login and takes every packet.
fn server() -> ScriptedConn {
    ScriptedConn::lines("# aprsc 2.1.14\r\n", |line| {
        line.starts_with("user ").then(|| "# logresp DF1JSL-15 verified, server T2TEST\r\n".to_string())
    })
}

fn send(target: &Target, msg: &Message) {
    let fake = FakeTransport::new();
    fake.push_conn(server());
    let d = target.send(msg, &fake, &Asset::default());
    assert!(d.is_success(), "{d:?}");
}

fn bench(c: &mut Criterion) {
    let one = mercurio::parse("aprs://DF1JSL-15:12345@DF1ABC").unwrap();
    let to: Vec<String> = (0..10).map(|i| format!("DF1AB{i}")).collect();
    let ten = mercurio::parse(&format!("aprs://DF1JSL-15:12345@{}", to.join("/"))).unwrap();
    let msg = Message::new("Disk almost full");

    let mut g = c.benchmark_group("aprs");
    g.bench_function("1_target", |b| b.iter_batched(|| (), |()| send(black_box(&one), &msg), BatchSize::SmallInput));
    g.bench_function("10_targets", |b| b.iter_batched(|| (), |()| send(black_box(&ten), &msg), BatchSize::SmallInput));
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
