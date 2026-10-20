//! The real transport against a local HTTP server (no internet needed).

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;

use mercurio::{BlockingTransport, Mercurio, Message, Method, Request, Transport};

type Captured = (String, Vec<(String, String)>, Vec<u8>);

/// Serve `n` requests; return each raw request through the channel.
fn server(n: usize, status: u16, body: &'static str) -> (String, mpsc::Receiver<Captured>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        for stream in listener.incoming().take(n) {
            let mut stream = stream.unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let mut headers = Vec::new();
            let mut len = 0;
            loop {
                let mut h = String::new();
                reader.read_line(&mut h).unwrap();
                let h = h.trim_end().to_string();
                if h.is_empty() {
                    break;
                }
                let (k, v) = h.split_once(':').unwrap();
                if k.eq_ignore_ascii_case("content-length") {
                    len = v.trim().parse().unwrap();
                }
                headers.push((k.to_string(), v.trim().to_string()));
            }
            let mut buf = vec![0; len];
            reader.read_exact(&mut buf).unwrap();
            tx.send((line.trim_end().to_string(), headers, buf)).unwrap();
            write!(
                stream,
                "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nX-Reply: yes\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        }
    });
    (format!("127.0.0.1:{}", addr.port()), rx)
}

#[test]
fn http_round_trip() {
    let (addr, rx) = server(1, 201, "{\"ok\":true}");
    let t = BlockingTransport::new();
    let req = Request::new(Method::Put, format!("http://{addr}/a/b?x=1"))
        .header("X-Test", "1")
        .json(&serde_json::json!({"k": "v"}));
    let res = t.http(&req).unwrap();
    assert_eq!(res.status, 201);
    assert_eq!(res.header("x-reply"), Some("yes"));
    assert_eq!(res.json().unwrap()["ok"], true);
    let (line, headers, body) = rx.recv().unwrap();
    assert_eq!(line, "PUT /a/b?x=1 HTTP/1.1");
    assert!(headers.iter().any(|(k, v)| k.eq_ignore_ascii_case("x-test") && v == "1"));
    assert!(headers.iter().any(|(k, v)| k.eq_ignore_ascii_case("user-agent") && v.starts_with("Mercurio/")));
    assert_eq!(body, br#"{"k":"v"}"#);
}

#[test]
fn error_status_is_returned_not_raised() {
    let (addr, _rx) = server(1, 503, "busy");
    let res = BlockingTransport::new().http(&Request::get(format!("http://{addr}/"))).unwrap();
    assert_eq!(res.status, 503);
    assert_eq!(res.text(), "busy");
}

#[test]
fn connection_refused_is_transport_error() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let err = BlockingTransport::new().http(&Request::get(format!("http://127.0.0.1:{port}/"))).unwrap_err();
    assert!(matches!(err, mercurio::Error::Transport(_)), "{err:?}");
}

#[test]
fn end_to_end_json_service() {
    let (addr, rx) = server(1, 200, "");
    let mut m = Mercurio::new();
    m.add(&format!("json://{addr}/hook")).unwrap();
    let report = m.notify(&Message::new("body").title("title"));
    assert!(report.is_success(), "{report:?}");
    let (line, _, body) = rx.recv().unwrap();
    assert_eq!(line, "POST /hook HTTP/1.1");
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["message"], "body");
}

/// A Unix stream socket (`path`, or a Linux abstract name after a leading NUL) through the blocking transport.
#[cfg(unix)]
fn unix_echo(path: &str, listener: std::os::unix::net::UnixListener) {
    thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let mut b = [0u8; 4];
        s.read_exact(&mut b).unwrap();
        s.write_all(&b).unwrap();
    });
    let mut conn = BlockingTransport::new().connect(&mercurio::Endpoint::unix(path)).unwrap();
    conn.write_all(b"ping").unwrap();
    let mut b = [0u8; 4];
    conn.read_exact(&mut b).unwrap();
    assert_eq!(&b, b"ping");
    assert!(conn.start_tls().is_err());
}

#[cfg(unix)]
#[test]
fn unix_socket_round_trip() {
    let dir = std::env::temp_dir().join(format!("mercurio-unix-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("echo.sock");
    let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
    unix_echo(&path.to_string_lossy(), listener);
    assert!(
        BlockingTransport::new().connect(&mercurio::Endpoint::unix(dir.join("missing").to_string_lossy())).is_err()
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn abstract_unix_socket_round_trip() {
    use std::os::linux::net::SocketAddrExt;
    let name = format!("mercurio-test-{}", std::process::id());
    let addr = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
    let listener = std::os::unix::net::UnixListener::bind_addr(&addr).unwrap();
    unix_echo(&format!("\0{name}"), listener);
}
