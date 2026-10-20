//! SMTP sessions against a scripted in-memory server: the protocol cost without a network.
//!
//! `cargo bench -p mercurio --bench smtp`
#![expect(clippy::unwrap_used, reason = "a bench fails loudly on bad setup")]

use std::hint::black_box;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use mercurio::testing::{FakeTransport, ScriptedConn};
use mercurio::{Asset, Message, Target};

/// A server that accepts everything: EHLO advertises AUTH and SIZE; DATA lines are swallowed until `.`.
fn server() -> ScriptedConn {
    let mut in_data = false;
    ScriptedConn::lines("220 bench ESMTP\r\n", move |line| {
        if in_data {
            if line == "." {
                in_data = false;
                return Some("250 2.0.0 queued\r\n".into());
            }
            return None;
        }
        let verb = line.split([' ', ':']).next().unwrap_or("").to_ascii_uppercase();
        Some(
            match verb.as_str() {
                "EHLO" => "250-bench\r\n250-AUTH PLAIN LOGIN\r\n250 SIZE 52428800\r\n",
                "AUTH" => "235 2.7.0 ok\r\n",
                "MAIL" | "RCPT" => "250 2.1.0 ok\r\n",
                "DATA" => {
                    in_data = true;
                    "354 go ahead\r\n"
                }
                "QUIT" => "221 bye\r\n",
                _ => "500 what\r\n",
            }
            .into(),
        )
    })
}

fn send(target: &Target, msg: &Message) {
    let fake = FakeTransport::new();
    fake.push_conn(server());
    let d = target.send(msg, &fake, &Asset::default());
    assert!(d.is_success(), "{d:?}");
}

fn bench(c: &mut Criterion) {
    let base = "mailto://user:pass@example.com:2525?mode=insecure&from=bot@example.com";
    let one = mercurio::parse(&format!("{base}&to=a@example.com")).unwrap();
    let to: Vec<String> = (0..50).map(|i| format!("r{i}@example.com")).collect();
    let fifty = mercurio::parse(&format!("{base}&to={}", to.join(","))).unwrap();
    let small = Message::new("Disk almost full").title("server-1");
    let line = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor.\n";
    let large = Message::new(line.repeat(256 * 1024 / line.len())).title("server-1");

    let mut g = c.benchmark_group("smtp");
    g.bench_function("1_rcpt", |b| b.iter_batched(|| (), |()| send(black_box(&one), &small), BatchSize::SmallInput));
    g.bench_function("50_rcpt", |b| b.iter_batched(|| (), |()| send(black_box(&fifty), &small), BatchSize::SmallInput));
    g.bench_function("256k_body", |b| b.iter_batched(|| (), |()| send(black_box(&one), &large), BatchSize::SmallInput));
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
