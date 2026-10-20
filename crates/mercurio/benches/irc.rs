//! IRC sessions against a scripted in-memory server: the protocol cost without a network.
//!
//! `cargo bench -p mercurio --bench irc`
#![expect(clippy::unwrap_used, reason = "a bench fails loudly on bad setup")]

use std::hint::black_box;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use mercurio::testing::{FakeTransport, ScriptedConn};
use mercurio::{Asset, Message, Target};

/// A server that welcomes after USER, confirms every JOIN and swallows everything else.
fn server() -> ScriptedConn {
    ScriptedConn::lines(":srv NOTICE * :*** hi\r\n", |line| {
        if line.starts_with("USER ") {
            return Some(":srv 001 me :Welcome\r\n:srv 376 me :End of MOTD\r\n".into());
        }
        let chan = line.strip_prefix("JOIN ")?.split(' ').next()?;
        Some(format!(":me!u@h JOIN :{chan}\r\n"))
    })
}

fn send(target: &Target, msg: &Message) {
    let fake = FakeTransport::new();
    fake.push_conn(server());
    let d = target.send(msg, &fake, &Asset::default());
    assert!(d.is_success(), "{d:?}");
}

fn bench(c: &mut Criterion) {
    let one = mercurio::parse("irc://me@irc.example.com/%23chan").unwrap();
    let chans: Vec<String> = (0..10).map(|i| format!("%23c{i}")).collect();
    let ten = mercurio::parse(&format!("irc://me@irc.example.com/{}", chans.join("/"))).unwrap();
    let small = Message::new("Disk almost full").title("server-1");
    let lines = Message::new("line of a longer report\n".repeat(20)).title("server-1");

    let mut g = c.benchmark_group("irc");
    g.bench_function("1_chan_1_line", |b| {
        b.iter_batched(|| (), |()| send(black_box(&one), &small), BatchSize::SmallInput)
    });
    g.bench_function("10_chan_20_lines", |b| {
        b.iter_batched(|| (), |()| send(black_box(&ten), &lines), BatchSize::SmallInput)
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
