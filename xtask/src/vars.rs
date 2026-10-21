//! Replaces `{{repository}}`, `{{pages}}` and `{{image}}` in every chapter

use std::io::Read;

use serde_json::Value;

pub fn run(args: &[&str]) -> Result<(), String> {
    if args.first() == Some(&"supports") {
        return Ok(());
    }
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input).map_err(|e| format!("stdin: {e}"))?;
    let mut pair: Value = serde_json::from_str(&input).map_err(|e| format!("mdbook input: {e}"))?;
    let mut book = pair.get_mut(1).map(Value::take).ok_or("mdbook input: no book")?;
    replace(&mut book);
    println!("{book}");
    Ok(())
}

pub fn fill(text: &str) -> String {
    let path = mercurio::asset::REPOSITORY_URL.trim_start_matches("https://github.com/").to_lowercase();
    text.replace("{{repository}}", mercurio::asset::REPOSITORY_URL)
        .replace("{{pages}}", mercurio::asset::PAGES_URL)
        .replace("{{description}}", env!("CARGO_PKG_DESCRIPTION"))
        .replace("{{image}}", &format!("ghcr.io/{path}"))
}

fn replace(v: &mut Value) {
    match v {
        Value::Object(m) => {
            for (k, item) in m.iter_mut() {
                if let (Value::String(s), "content") = (&mut *item, k.as_str()) {
                    *s = fill(s);
                } else {
                    replace(item);
                }
            }
        }
        Value::Array(a) => a.iter_mut().for_each(replace),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}
