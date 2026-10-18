//! IRC line parsing helpers.

/// A parsed IRC line: `[":" prefix " "] command params [" :" trailing]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrcMessage {
    pub prefix: Option<String>,
    pub command: String,
    pub params: Vec<String>,
    pub trailing: Option<String>,
}

impl IrcMessage {
    /// Three-digit numeric replies as an integer.
    pub fn numeric(&self) -> Option<u16> {
        (self.command.len() == 3 && self.command.bytes().all(|b| b.is_ascii_digit()))
            .then(|| self.command.parse().ok())
            .flatten()
    }

    pub fn is(&self, command: &str) -> bool {
        self.command.eq_ignore_ascii_case(command)
    }

    /// Payload to echo in a PONG.
    pub fn ping_payload(&self) -> &str {
        self.trailing.as_deref().or(self.params.first().map(String::as_str)).unwrap_or("")
    }

    /// Human readable error text.
    pub fn error_text(&self) -> String {
        match &self.trailing {
            Some(t) if !t.is_empty() => t.clone(),
            _ if !self.params.is_empty() => self.params.join(" "),
            _ => "IRC error".into(),
        }
    }
}

/// Parse one IRC line into prefix, command and parameters.
pub fn parse_line(line: &str) -> IrcMessage {
    let raw = line.trim_end_matches(['\r', '\n']);
    let mut s = raw;
    let mut prefix = None;
    if let Some(rest) = s.strip_prefix(':') {
        match rest.split_once(' ') {
            Some((p, r)) => {
                prefix = Some(p.to_string());
                s = r;
            }
            None => {
                prefix = Some(rest.to_string());
                s = "";
            }
        }
    }
    let mut trailing = None;
    if let Some((before, after)) = s.split_once(" :") {
        trailing = Some(after.to_string());
        s = before;
    }
    let mut bits = s.split_whitespace();
    let command = bits.next().unwrap_or("").to_string();
    let params = bits.map(str::to_string).collect();
    IrcMessage { prefix, command, params, trailing }
}

/// Ensure a leading `#`.
pub fn normalise_channel(name: &str) -> String {
    let name = name.trim();
    if name.is_empty() || name.starts_with('#') { name.to_string() } else { format!("#{name}") }
}

/// Registration failures.
pub fn register_error(n: u16) -> Option<&'static str> {
    Some(match n {
        464 => "Password incorrect",
        465 => "Banned from server",
        468 => "Only registered users allowed",
        _ => return None,
    })
}

/// Join failures.
pub fn join_error(n: u16) -> Option<&'static str> {
    Some(match n {
        403 => "No such channel",
        471 => "Channel is full",
        473 => "Invite only channel",
        474 => "Banned from channel",
        475 => "Bad channel key",
        476 => "Bad channel mask",
        477 => "Need to be registered",
        489 => "Cannot join channel",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_lines() {
        let m = parse_line(":server.example 001 nick :Welcome to the network\r\n");
        assert_eq!(m.prefix.as_deref(), Some("server.example"));
        assert_eq!(m.numeric(), Some(1));
        assert_eq!(m.params, vec!["nick"]);
        assert_eq!(m.trailing.as_deref(), Some("Welcome to the network"));

        let p = parse_line("PING :123456");
        assert!(p.is("ping"));
        assert_eq!(p.ping_payload(), "123456");
        assert_eq!(parse_line("PING abc").ping_payload(), "abc");

        let j = parse_line(":nick!user@host JOIN :#channel");
        assert!(j.is("JOIN"));
        assert_eq!(j.trailing.as_deref(), Some("#channel"));

        let e = parse_line(":srv 366 me #chan :End of /NAMES list.");
        assert_eq!(e.params, vec!["me", "#chan"]);
        assert_eq!(parse_line(":only").command, "");
        assert_eq!(parse_line("").numeric(), None);
        assert_eq!(parse_line("1234 x").numeric(), None);
    }

    #[test]
    fn channels() {
        assert_eq!(normalise_channel(" chan "), "#chan");
        assert_eq!(normalise_channel("#chan"), "#chan");
        assert_eq!(normalise_channel(""), "");
    }
}
