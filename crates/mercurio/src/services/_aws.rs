//! Helpers shared by `sns` and `ses`: AWS Signature Version 4 for their form-encoded query APIs and a flattener for their XML replies.

use std::collections::BTreeMap;

use crate::Result;
use crate::crypto::{hex, hmac_sha256, sha256, utc_parts};
use crate::error::Error;
use crate::http::Response;

/// Credentials and endpoint of one AWS query API.
#[derive(Debug, Clone, Copy)]
pub struct AwsSigner<'a> {
    pub access_key_id: &'a str,
    pub secret_access_key: &'a str,
    pub region: &'a str,
    /// e.g. `sns`, `ses`.
    pub service: &'a str,
    /// Value of the signed `host` header, e.g. `sns.us-east-1.amazonaws.com`.
    pub host: &'a str,
    /// Session token for temporary credentials (`X-Amz-Security-Token`).
    pub session_token: Option<&'a str>,
}

/// `Content-Type` sent (and signed) for AWS query APIs.
pub const AWS_FORM_CONTENT_TYPE: &str = "application/x-www-form-urlencoded; charset=utf-8";

/// `(YYYYMMDDTHHMMSSZ, YYYYMMDD)` for a Unix time.
pub fn amz_dates(secs: u64) -> (String, String) {
    let (y, mo, d, h, mi, s) = utc_parts(secs);
    (format!("{y:04}{mo:02}{d:02}T{h:02}{mi:02}{s:02}Z"), format!("{y:04}{mo:02}{d:02}"))
}

impl AwsSigner<'_> {
    /// Headers for a signed `POST /` with the already form-encoded `payload` and the given `content_type`, at Unix time `now`. Order: Content-Type, X-Amz-Date, [X-Amz-Security-Token], Authorization.
    pub fn sign_post(&self, payload: &str, content_type: &str, now: u64) -> Vec<(String, String)> {
        let (amzdate, date) = amz_dates(now);
        let scope = format!("{date}/{}/{}/aws4_request", self.region, self.service);
        let mut signed: Vec<(&str, &str)> =
            vec![("content-type", content_type), ("host", self.host), ("x-amz-date", &amzdate)];
        if let Some(t) = self.session_token {
            signed.push(("x-amz-security-token", t));
        }
        let names = signed.iter().map(|(k, _)| *k).collect::<Vec<_>>().join(";");
        let canonical_headers: String = signed.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
        let canonical = ["POST", "/", "", &canonical_headers, &names, &hex(&sha256(payload.as_bytes()))].join("\n");
        let to_sign = ["AWS4-HMAC-SHA256", &amzdate, &scope, &hex(&sha256(canonical.as_bytes()))].join("\n");

        let k_date = hmac_sha256(format!("AWS4{}", self.secret_access_key).as_bytes(), date.as_bytes());
        let k_region = hmac_sha256(&k_date, self.region.as_bytes());
        let k_service = hmac_sha256(&k_region, self.service.as_bytes());
        let k_signing = hmac_sha256(&k_service, b"aws4_request");
        let signature = hex(&hmac_sha256(&k_signing, to_sign.as_bytes()));

        let mut headers = vec![
            ("Content-Type".to_string(), content_type.to_string()),
            ("X-Amz-Date".to_string(), amzdate.clone()),
        ];
        if let Some(t) = self.session_token {
            headers.push(("X-Amz-Security-Token".to_string(), t.to_string()));
        }
        headers.push((
            "Authorization".to_string(),
            format!(
                "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={names}, Signature={signature}",
                self.access_key_id
            ),
        ));
        headers
    }
}

/// Checks an AWS region name (`us-east-1`, ...): returns the normalised region.
pub fn aws_region(entry: &str) -> Option<String> {
    let c = crate::regex!(r"(?i)^\s*(?P<country>[a-z]{2})-(?P<area>[a-z-]+?)-(?P<no>[0-9]+)\s*$").captures(entry)?;
    Some(format!("{}-{}-{}", c["country"].to_lowercase(), c["area"].to_lowercase(), &c["no"]))
}

/// Accept a 200 response. A 403 reports bad credentials; AWS throttling (`Throttling` / `ThrottlingException` error codes or a 429) becomes [`Error::RateLimited`] so the caller can retry.
pub fn aws_check(res: Result<Response>) -> Result<Response> {
    let r = res?;
    match r.status {
        200 => Ok(r),
        403 => Err(Error::Http { status: 403, reason: "Unauthorized - Invalid Access/Secret Key Combination.".into() }),
        _ if r.status == 429 || (r.status == 400 && r.text().contains("<Code>Throttling")) => {
            Err(Error::RateLimited { status: r.status, reason: r.snippet(), retry_after: r.retry_after() })
        }
        _ => Err(r.http_error()),
    }
}

/// Text of the leaf elements named in `keep` (tag -> key). `None` when the document is not well-formed XML (callers then keep only their defaults).
pub fn flatten_xml(xml: &str, keep: &[(&str, &str)]) -> Option<BTreeMap<String, String>> {
    use quick_xml::events::Event;
    let kept = |tag: &str| keep.iter().find(|(t, _)| *t == tag).map(|(_, k)| k.to_string());
    let mut found = BTreeMap::new();
    let mut stack: Vec<XmlEl> = Vec::new();
    let mut root_seen = false;
    let mut reader = quick_xml::Reader::from_str(xml.strip_prefix('\u{feff}').unwrap_or(xml));
    loop {
        match reader.read_event().ok()? {
            Event::Start(e) => {
                let tag = XmlEl::open(e.name().as_ref(), &mut stack, &mut root_seen)?;
                stack.push(XmlEl { tag, text: String::new(), leaf: true });
            }
            Event::Empty(e) => {
                let tag = XmlEl::open(e.name().as_ref(), &mut stack, &mut root_seen)?;
                if let Some(key) = kept(&tag) {
                    found.insert(key, String::new());
                }
            }
            Event::End(_) => {
                let el = stack.pop()?;
                if el.leaf
                    && let Some(key) = kept(&el.tag)
                {
                    found.insert(key, el.text.trim().to_string());
                }
            }
            Event::Text(t) => {
                let text = t.into_inner();
                match stack.last_mut() {
                    Some(el) => el.text.push_str(&text),
                    None if text.trim().is_empty() => {}
                    None => return None,
                }
            }
            // `&name;` and `&#n;` between text; only the XML entities resolve.
            Event::GeneralRef(r) => {
                let text = quick_xml::escape::unescape(&format!("&{};", r.into_inner())).ok()?.into_owned();
                stack.last_mut()?.text.push_str(&text);
            }
            Event::CData(c) => stack.last_mut()?.text.push_str(&c.into_inner()),
            Event::DocType(_) => return None,
            Event::Comment(_) | Event::Decl(_) | Event::PI(_) => {}
            Event::Eof => break,
        }
    }
    (root_seen && stack.is_empty()).then_some(found)
}

/// An open element while flattening.
struct XmlEl {
    tag: String,
    text: String,
    leaf: bool,
}

impl XmlEl {
    /// Validate a start tag: a well-formed name and a single root element.
    fn open(tag: &str, stack: &mut [XmlEl], root_seen: &mut bool) -> Option<String> {
        let mut chars = tag.chars();
        let valid = chars.next().is_some_and(|c| c.is_alphabetic() || c == '_' || c == ':')
            && chars.all(|c| c.is_alphanumeric() || matches!(c, '_' | ':' | '-' | '.'));
        match stack.last_mut() {
            _ if !valid => return None,
            Some(parent) => parent.leaf = false,
            None if *root_seen => return None,
            None => *root_seen = true,
        }
        Some(tag.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AWS SigV4 test suite: `post-x-www-form-urlencoded`.
    #[test]
    fn sigv4_test_suite_post_form() {
        let signer = AwsSigner {
            access_key_id: "AKIDEXAMPLE",
            secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            region: "us-east-1",
            service: "service",
            host: "example.amazonaws.com",
            session_token: None,
        };
        // 2015-08-30T12:36:00Z
        let h = signer.sign_post("Param1=value1", "application/x-www-form-urlencoded", 1_440_938_160);
        assert_eq!(h[1], ("X-Amz-Date".into(), "20150830T123600Z".into()));
        assert_eq!(
            h.last().unwrap().1,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
             SignedHeaders=content-type;host;x-amz-date, \
             Signature=ff11897932ad3f4e8b18135d722051e5ac45fc38421b1da7b9d196a0fe09473a"
        );
    }

    /// AWS documentation's signing-key derivation example (`iam`, 20150830).
    #[test]
    fn sigv4_signing_key() {
        let k_date = hmac_sha256(b"AWS4wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", b"20150830");
        let k_region = hmac_sha256(&k_date, b"us-east-1");
        let k_service = hmac_sha256(&k_region, b"iam");
        let k_signing = hmac_sha256(&k_service, b"aws4_request");
        assert_eq!(hex(&k_signing), "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9");
    }

    #[test]
    fn throttling_is_retryable() {
        use crate::error::ErrorClass;
        let body = b"<ErrorResponse><Error><Type>Sender</Type><Code>Throttling</Code>\
                     <Message>Maximum sending rate exceeded.</Message></Error></ErrorResponse>";
        let err = aws_check(Ok(Response::new(400, body.to_vec()))).unwrap_err();
        assert_eq!(err.class(), ErrorClass::RateLimited { retry_after: None });
        let err = aws_check(Ok(Response::new(503, Vec::new()))).unwrap_err();
        assert_eq!(err.class(), ErrorClass::Transient);
        let err = aws_check(Ok(Response::new(400, b"<Code>InvalidParameterValue</Code>".to_vec()))).unwrap_err();
        assert!(!err.class().is_retryable());
    }

    #[test]
    fn session_token_is_signed() {
        let signer = AwsSigner {
            access_key_id: "AKID",
            secret_access_key: "secret",
            region: "us-west-2",
            service: "sns",
            host: "sns.us-west-2.amazonaws.com",
            session_token: Some("TOKEN"),
        };
        let h = signer.sign_post("Action=Publish", AWS_FORM_CONTENT_TYPE, 0);
        assert_eq!(h[2], ("X-Amz-Security-Token".into(), "TOKEN".into()));
        assert!(h[3].1.contains("SignedHeaders=content-type;host;x-amz-date;x-amz-security-token,"));
        assert_eq!(amz_dates(0), ("19700101T000000Z".into(), "19700101".into()));
    }

    /// Reference signatures for fixed inputs, with the clock fixed at 2026-10-16T12:00:00Z (sns with a session token, ses without).
    #[test]
    fn sigv4_matches_reference() {
        let payload = "Action=Publish&Message=Hello+World&Version=2010-03-31&PhoneNumber=%2B12223334444";
        let mut signer = AwsSigner {
            access_key_id: "AKIDEXAMPLE",
            secret_access_key: "wJalr/XUtn",
            region: "us-west-2",
            service: "sns",
            host: "sns.us-west-2.amazonaws.com",
            session_token: Some("TOKEN/1"),
        };
        let h = signer.sign_post(payload, AWS_FORM_CONTENT_TYPE, 1_792_152_000);
        assert_eq!(h[1].1, "20261016T120000Z");
        assert_eq!(
            h[3].1,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261016/us-west-2/sns/aws4_request, \
             SignedHeaders=content-type;host;x-amz-date;x-amz-security-token, \
             Signature=261933cae256cef2ac4b522c8aff438a53047c7f50baf10552101f07e6b94de8"
        );
        signer.service = "ses";
        signer.host = "email.us-west-2.amazonaws.com";
        signer.session_token = None;
        let h = signer.sign_post(payload, AWS_FORM_CONTENT_TYPE, 1_792_152_000);
        assert_eq!(
            h[2].1,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261016/us-west-2/ses/aws4_request, \
             SignedHeaders=content-type;host;x-amz-date, \
             Signature=a359ba1a09a3282bf3f4f2adaea8476e3dc8b0a3632e8cd208c44a6c35b01679"
        );
    }

    #[test]
    fn regions() {
        assert_eq!(aws_region(" US-East-1 ").as_deref(), Some("us-east-1"));
        assert_eq!(aws_region("cn-north-1").as_deref(), Some("cn-north-1"));
        assert_eq!(aws_region("us-east"), None);
    }

    #[test]
    fn xml() {
        let keep = [("TopicArn", "topic_arn"), ("RequestId", "request_id"), ("Message", "error_message")];
        let doc = r#"<?xml version="1.0"?>
            <CreateTopicResponse xmlns="http://sns.amazonaws.com/doc/2010-03-31/">
              <CreateTopicResult><TopicArn> arn:aws:sns:us-east-1:000000000000:abcd </TopicArn></CreateTopicResult>
              <ResponseMetadata><RequestId>604b&amp;ef0f</RequestId></ResponseMetadata>
              <Message/>
            </CreateTopicResponse>"#;
        let m = flatten_xml(doc, &keep).unwrap();
        assert_eq!(m["topic_arn"], "arn:aws:sns:us-east-1:000000000000:abcd");
        assert_eq!(m["request_id"], "604b&ef0f");
        assert_eq!(m["error_message"], "");
        assert!(flatten_xml("{}", &keep).is_none());
        assert!(flatten_xml("", &keep).is_none());
        assert!(flatten_xml("<a><b></a>", &keep).is_none());
        assert!(flatten_xml("<!DOCTYPE x><a/>", &keep).is_none());
        assert!(flatten_xml("<a/><b/>", &keep).is_none());
        // Branch elements are not kept.
        let m = flatten_xml("<r><TopicArn><x>1</x></TopicArn></r>", &keep).unwrap();
        assert!(!m.contains_key("topic_arn"));
    }
}
