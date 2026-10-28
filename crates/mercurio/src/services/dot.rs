//! Dot. (`dot://`): text and image content pushed to a Dot. device through the MindReset API.

use serde_json::{Value, json};

use crate::crypto::b64;
use crate::http::Request;
use crate::parse::parse_bool;
use crate::service::{Context, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, unquote};
use crate::{Error, Plan, Prepared, Result};

pub(crate) static SERVICE: ServiceDef = ServiceDef {
    id: "dot",
    name: "Dot.",
    schemes: &["dot"],
    service_url: "https://dot.mindreset.tech",
    parse,
    attachments: true,
    templates: &[
        "{schema}://{apikey}@{device_id}/",
    ],
    tokens: &[
        Param::new("apikey", "API Key").required().secret(),
        Param::new("device_id", "Device Serial Number").required(),
    ],
    params: &[
        Param::new("border", "Border").int().default("0").range(0, 1).inferred(),
        Param::new("dither_kernel", "Dither Kernel").choice(&["THRESHOLD", "ATKINSON", "BURKES", "FLOYD_STEINBERG", "SIERRA2", "STUCKI", "JARVIS_JUDICE_NINKE", "DIFFUSION_ROW", "DIFFUSION_COLUMN", "DIFFUSION_2D"]).default("FLOYD_STEINBERG").inferred(),
        Param::new("dither_type", "Dither Type").choice(&["DIFFUSION", "ORDERED", "NONE"]).default("DIFFUSION").inferred(),
        Param::new("icon", "Icon Base64 (Text API)"),
        Param::new("image", "Image Base64 (Image API)"),
        Param::new("link", "Link"),
        Param::new("mode", "API Mode").choice(&["text", "image"]).default("text").inferred(),
        Param::new("refresh", "Refresh Now").bool(true),
        Param::new("signature", "Text Signature"),
        Param::new("task_key", "Task Key"),
    ],
    ..ServiceDef::DEFAULTS
};

const MODES: &[&str] = &["text", "image"];

#[derive(Debug)]
struct Dot {
    apikey: Option<Secret>,
    device_id: Option<String>,
    image_mode: bool,
    refresh_now: bool,
    signature: Option<String>,
    icon: Option<String>,
    image_data: Option<String>,
    link: Option<String>,
    border: Option<i64>,
    dither_type: Option<String>,
    dither_kernel: Option<String>,
    task_key: Option<String>,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    crate::parse::require_host(u, &SERVICE)?;
    let q = |k: &str| u.param_nonempty(k).map(|v| unquote(v.trim()));
    let mode = match u.param_nonempty("mode") {
        Some(m) => m.to_lowercase().trim().to_owned(),
        None => u.path_segments().first().map(|s| s.to_lowercase()).unwrap_or_default(),
    };
    let image_mode = MODES.contains(&mode.as_str()) && mode == "image";
    Ok(Box::new(Dot {
        apikey: u.user.as_deref().filter(|s| !s.is_empty()).map(|s| Secret::new(unquote(s))),
        device_id: Some(u.host.as_str()).filter(|s| !s.is_empty()).map(unquote).filter(|s| !s.is_empty()),
        image_mode,
        refresh_now: u.param_nonempty("refresh").map(|v| parse_bool(v.trim(), false)).unwrap_or(true),
        signature: q("signature"),
        icon: q("icon"),
        image_data: q("image").filter(|s| !s.is_empty()),
        link: q("link"),
        border: SERVICE.int(u, "border"),
        dither_type: q("dither_type"),
        dither_kernel: q("dither_kernel"),
        task_key: q("task_key").filter(|s| !s.is_empty()),
    }))
}

impl Dot {
    fn post(&self, url: String, payload: &Value, apikey: &str, ctx: &Context<'_>) -> Plan {
        let req = Request::post(url)
            .header("Authorization", format!("Bearer {apikey}"))
            .header("User-Agent", ctx.app_id())
            .json(payload);
        Plan::send_expect(req, &[200])
    }

    fn image_plan(&self, base: &str, image: String, apikey: &str, ctx: &Context<'_>) -> Plan {
        let mut payload = json!({"image": image, "refreshNow": self.refresh_now});
        if let Some(v) = self.link.as_ref().filter(|s| !s.is_empty()) {
            payload["link"] = json!(v);
        }
        if let Some(v) = self.border {
            payload["border"] = json!(v);
        }
        if let Some(v) = &self.dither_type {
            payload["ditherType"] = json!(v);
        }
        if let Some(v) = &self.dither_kernel {
            payload["ditherKernel"] = json!(v);
        }
        if let Some(v) = &self.task_key {
            payload["taskKey"] = json!(v);
        }
        self.post(format!("{base}/image"), &payload, apikey, ctx)
    }
}

impl Notify for Dot {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let (Some(apikey), Some(device)) = (&self.apikey, &self.device_id) else {
            return Plan::Fail(Error::Service("no Dot API key or device id was specified".into()));
        };
        let apikey = apikey.expose();
        let base = format!("https://dot.mindreset.tech/api/authV2/open/device/{device}");
        let image = self.image_data.clone().or_else(|| msg.attachments.first().map(|a| b64(&a.data)));
        if self.image_mode {
            return match image.filter(|s| !s.is_empty()) {
                Some(img) => self.image_plan(&base, img, apikey, ctx),
                None => Plan::Fail(Error::Service("image mode selected but no image data was provided".into())),
            };
        }
        let has_text = !msg.body.is_empty() || !msg.title.is_empty();
        let image = image.filter(|s| !s.is_empty());
        if !has_text && image.is_none() {
            return Plan::Fail(Error::Service("nothing to send to the Dot device".into()));
        }
        let mut plans = Vec::new();
        if has_text {
            let mut payload = json!({"refreshNow": self.refresh_now});
            if !msg.title.is_empty() {
                payload["title"] = json!(msg.title);
            }
            if !msg.body.is_empty() {
                payload["message"] = json!(msg.body);
            }
            for (key, v) in [("signature", &self.signature), ("icon", &self.icon), ("link", &self.link)] {
                if let Some(v) = v.as_ref().filter(|s| !s.is_empty()) {
                    payload[key] = json!(v);
                }
            }
            if let Some(v) = &self.task_key {
                payload["taskKey"] = json!(v);
            }
            plans.push(self.post(format!("{base}/text"), &payload, apikey, ctx));
        }
        if let Some(img) = image {
            plans.push(self.image_plan(&base, img, apikey, ctx));
        }
        Plan::all(plans)
    }

}
