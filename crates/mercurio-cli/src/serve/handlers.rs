//! The business logic behind each operation, one module per area.
//!
//! The generated `Api` is implemented here: each operation reads its typed parameters, calls its handler on
//! [`Server`] and answers with its typed response.

pub(crate) mod auth;
pub(crate) mod config;
mod key;
pub(crate) mod notify;
pub(crate) mod status;

use serde_json::{Map, Value};

use super::Server;
use super::api::operations as ops;
use super::api::{self, types};
use super::call::{Call, Caller, Fault, fault_response};
use super::notify::{Delivered, Logs};
use super::payload::{NotifyBody, NotifyInput};
use super::router::Api;
use auth::AuthChanged;
use config::{Listing, MoveTo, NewConfig, Saved, Stored, Urls};
use notify::{SendHeaders, Sent};

type Ctx<'a, 'b> = &'a api::server::Context<'b, Option<std::sync::Arc<Caller>>>;

fault_response!(status: 400 => BadRequest, 403 => Forbidden; other => BadRequest);
fault_response!(status_key: 400 => BadRequest, 403 => Forbidden, 404 => NotFound; other => BadRequest);
fault_response!(status_current: 400 => BadRequest; other => BadRequest);
fault_response!(details: 400 => BadRequest, 403 => Forbidden; other => BadRequest);
fault_response!(list_configs: 403 => Forbidden; other => Forbidden);
fault_response!(config_current: 400 => BadRequest; other => BadRequest);
fault_response!(config_current_post: 400 => BadRequest; other => BadRequest);
fault_response!(auth_current: 400 => BadRequest; other => BadRequest);
fault_response!(auth_current_post: 400 => BadRequest; other => BadRequest);
fault_response!(auth_current_delete: 400 => BadRequest; other => BadRequest);

/// The statuses every configuration and `/auth` operation declares.
macro_rules! config_faults {
    ($($op:ident),*) => {$(
        fault_response!($op: 400 => BadRequest, 403 => Forbidden, 404 => NotFound, 500 => InternalServerError; other => BadRequest);
    )*};
}
config_faults!(
    config_alias,
    get_config,
    get_config_by_header,
    add_config,
    add_config_by_header,
    delete_config,
    delete_config_by_header,
    set_auth,
    set_auth_by_header,
    delete_auth,
    delete_auth_by_header
);

/// `/json/urls` answers a configuration it cannot read with the list's own shape.
macro_rules! urls_faults {
    ($($op:ident),*) => {$(
        impl From<Fault> for ops::$op::Response {
            fn from(f: Fault) -> Self {
                use ops::$op::Response;
                match f.status {
                    401 => Response::Unauthorized { body: f.body(), www_authenticate: f.challenge.clone() },
                    403 => Response::Forbidden(f.body()),
                    404 => Response::NotFound(f.body()),
                    500 => Response::InternalServerError(types::JsonUrls { error: Some(f.message), tags: vec![], urls: vec![] }),
                    _ => Response::BadRequest(f.body()),
                }
            }
        }
    )*};
}
urls_faults!(json_urls, json_urls_by_header);
fault_response!(get_auth: 400 => BadRequest, 403 => Forbidden, 404 => NotFound; other => BadRequest);
fault_response!(get_auth_by_header: 400 => BadRequest, 403 => Forbidden, 404 => NotFound; other => BadRequest);
fault_response!(move_config: 400 => BadRequest, 403 => Forbidden, 404 => NotFound, 409 => Conflict, 424 => FailedDependency, 500 => InternalServerError; other => BadRequest);
fault_response!(move_config_by_header: 400 => BadRequest, 403 => Forbidden, 404 => NotFound, 409 => Conflict, 424 => FailedDependency, 500 => InternalServerError; other => BadRequest);

/// The statuses of a send; `503` carries its `Retry-After`.
macro_rules! notify_faults {
    ($($op:ident),*) => {$(
        impl From<Fault> for ops::$op::Response {
            fn from(f: Fault) -> Self {
                use ops::$op::Response;
                match f.status {
                    401 => Response::Unauthorized { body: f.body(), www_authenticate: f.challenge.clone() },
                    403 => Response::Forbidden(f.body()),
                    404 => Response::NotFound(f.body()),
                    406 => Response::NotAcceptable(f.body()),
                    413 => Response::PayloadTooLarge(f.body()),
                    431 => Response::RequestHeaderFieldsTooLarge(f.body()),
                    500 => Response::InternalServerError(f.body()),
                    503 => Response::ServiceUnavailable { body: f.body(), retry_after: f.retry_after },
                    _ => Response::BadRequest(f.body()),
                }
            }
        }

        impl From<Sent> for ops::$op::Response {
            fn from(sent: Sent) -> Self {
                use ops::$op::{FailedDependencyBody as Failed, OkBody, Response};
                match sent {
                    Sent::Stream(items) => Response::Ok {
                        body: OkBody::EventStream(items),
                        cache_control: Some("no-cache".to_owned()),
                        x_accel_buffering: Some("no".to_owned()),
                    },
                    Sent::Done(Delivered { ok: true, logs }) => {
                        let body = match logs {
                            Logs::Text(t) => OkBody::Plain(t),
                            Logs::Html(h) => OkBody::Html(h),
                            Logs::Json(j) => OkBody::Json(j),
                        };
                        Response::Ok { body, cache_control: None, x_accel_buffering: None }
                    }
                    Sent::Done(Delivered { ok: false, logs }) => Response::FailedDependency(match logs {
                        Logs::Text(t) => Failed::Plain(t),
                        Logs::Html(h) => Failed::Html(h),
                        Logs::Json(j) => Failed::Json(j),
                    }),
                }
            }
        }
    )*};
}
notify_faults!(notify, notify_stateless);

/// `Ok(answer)` or the fault as the operation's response.
fn answer<R: From<Fault>>(result: Result<R, Fault>) -> Result<R, api::ApiError> {
    Ok(result.unwrap_or_else(R::from))
}

/// The business behind the generated server.
fn server(api: &Api) -> &Server {
    &api.0
}

/// The `X-Apprise-Config-ID` header, when not empty: the spec has checked it.
fn config_id(header: Option<&types::ConfigIdHeader>) -> Option<&str> {
    header.map(types::ConfigIdHeader::as_str).filter(|h| !h.is_empty())
}

/// The text fields of a form or multipart body, and the ones it does not declare.
fn text_fields(
    known: [(&str, Option<String>); 7],
    others: impl IntoIterator<Item = (String, String)>,
) -> Map<String, Value> {
    let mut map: Map<String, Value> = others.into_iter().map(|(k, v)| (k, Value::String(v))).collect();
    for (k, v) in known {
        if let Some(v) = v {
            map.insert(k.to_owned(), Value::String(v));
        }
    }
    map
}

/// The first of `attach`, `attachment` and `attachments` given: apprise-api reads only one.
fn first_attach<T>(fields: [Option<Vec<T>>; 3]) -> Option<Vec<T>> {
    fields.into_iter().flatten().next()
}

/// A form body's fields, `template[NAME]` values and attachment fields.
macro_rules! form_body {
    ($f:expr, $urls:expr) => {{
        let f = $f;
        let urls = $urls(&f);
        let fields = text_fields(
            [
                ("body", f.body),
                ("title", f.title),
                ("type", f.type_),
                ("format", f.format),
                ("tag", f.tag),
                ("tags", f.tags),
                ("urls", urls),
            ],
            f.additional_properties,
        );
        NotifyBody::Form {
            fields,
            template: f.template.unwrap_or_default(),
            attach: first_attach([f.attach, f.attachment, f.attachments]),
        }
    }};
}

/// A multipart body's text fields, attachment fields and files.
macro_rules! multipart_body {
    ($f:expr, $urls:expr) => {{
        let f = $f;
        let urls = $urls(&f);
        let fields = text_fields(
            [
                ("body", f.body),
                ("title", f.title),
                ("type", f.type_),
                ("format", f.format),
                ("tag", f.tag),
                ("tags", f.tags),
                ("urls", urls),
            ],
            [],
        );
        NotifyBody::multipart(fields, [f.attach, f.attachment, f.attachments], f.additional_properties)
    }};
}

/// `/get`, `/cfg/{key}`: the stored configuration, or `204`.
macro_rules! stored {
    ($api:expr, $ctx:expr, $op:ident, $header:expr, $path:expr) => {{
        use ops::$op::{OkBody, Response};
        let call = Call::new($ctx);
        answer(server($api).get_config(&call, $header, $path).await.map(|s| match s {
            None => Response::NoContent,
            Some(Stored::Text(t)) => Response::Ok(OkBody::Plain(t)),
            Some(Stored::Yaml(t)) => Response::Ok(OkBody::Yaml(t)),
            Some(Stored::Json(j)) => Response::Ok(OkBody::Json(j)),
        }))
    }};
}

/// `/add`: the configuration a JSON, form or multipart body carries.
macro_rules! saved {
    ($api:expr, $ctx:expr, $op:ident, $p:ident, $path:expr) => {{
        use ops::$op::{Body, Response};
        let call = Call::new($ctx);
        let new = $p.body.map(|b| match b {
            Body::Json(j) => NewConfig { urls: j.urls, config: j.config, format: j.format },
            Body::XWwwFormUrlencoded(f) | Body::FormData(f) => {
                NewConfig { urls: f.urls.map(types::Strings::String), config: f.config, format: f.format }
            }
        });
        let saved = server($api).add(&call, config_id($p.x_apprise_config_id.as_ref()), $path, new).await;
        answer(saved.map(|Saved { body, created, modified }| Response::Ok {
            body,
            x_apprise_config_created: created,
            x_apprise_config_m_time: modified,
            x_apprise_timezone: Some("Etc/UTC".to_owned()),
        }))
    }};
}

/// `/del`: done, or `204` when nothing was stored.
macro_rules! deleted {
    ($api:expr, $ctx:expr, $op:ident, $header:expr, $path:expr) => {{
        use ops::$op::Response;
        let call = Call::new($ctx);
        answer(server($api).del(&call, $header, $path).await.map(|d| d.map_or(Response::NoContent, Response::Ok)))
    }};
}

/// `/move`: the destination from JSON, or the source and destination from a form.
macro_rules! moved {
    ($api:expr, $ctx:expr, $op:ident, $p:ident, $path:expr) => {{
        use ops::$op::{Body, Response};
        let call = Call::new($ctx);
        let to = match $p.body {
            Some(Body::Json(j)) => MoveTo::Json(j.to),
            Some(Body::XWwwFormUrlencoded(f) | Body::FormData(f)) => MoveTo::Form { from: f.from, to: f.to },
            None if call.json => MoveTo::Json(None),
            None => MoveTo::Form { from: None, to: None },
        };
        answer(
            server($api)
                .move_config(&call, config_id($p.x_apprise_config_id.as_ref()), $path, to)
                .await
                .map(Response::Ok),
        )
    }};
}

/// `/auth` changes: text or `{"error": null, "auth_state": ...}`.
macro_rules! auth_changed {
    ($api:expr, $ctx:expr, $op:ident, $handler:ident, $header:expr, $path:expr $(, $body:expr)?) => {{
        use ops::$op::{OkBody, Response};
        let call = Call::new($ctx);
        answer(server($api).$handler(&call, $header, $path $(, $body)?).await.map(|c| {
            Response::Ok(match c {
                AuthChanged::Text(t) => OkBody::Plain(t),
                AuthChanged::Json(j) => OkBody::Json(j),
            })
        }))
    }};
}

/// `/json/urls`: the URLs, `204` when nothing is stored, `500` with an empty list when it cannot be read.
macro_rules! urls {
    ($api:expr, $ctx:expr, $op:ident, $p:ident, $path:expr) => {{
        use ops::$op::Response;
        let call = Call::new($ctx);
        let found = server($api)
            .json_urls(
                &call,
                config_id($p.x_apprise_config_id.as_ref()),
                $path,
                $p.privacy.as_deref(),
                $p.tag.as_deref(),
            )
            .await;
        answer(found.map(|u| match u {
            Urls::Found(j) => Response::Ok(j),
            Urls::Empty => Response::NoContent,
            Urls::Unreadable(j) => Response::InternalServerError(j),
        }))
    }};
}

/// `/status/@`, `/cfg/@`, `/auth/@`: the current Config ID, which an API call never has.
macro_rules! current_key {
    ($($op:ident),*) => {$(
        async fn $op(&self, _: ops::$op::Params, ctx: Ctx<'_, '_>) -> Result<ops::$op::Response, api::ApiError> {
            answer(Err(Server::current_key(&Call::new(ctx))))
        }
    )*};
}

impl api::server::Api for Api {
    type Principal = std::sync::Arc<Caller>;

    current_key!(
        status_current,
        config_current,
        config_current_post,
        auth_current,
        auth_current_post,
        auth_current_delete
    );

    async fn status(&self, p: ops::status::Params, ctx: Ctx<'_, '_>) -> Result<ops::status::Response, api::ApiError> {
        let call = Call::new(ctx);
        answer(
            server(self)
                .status(&call, config_id(p.x_apprise_config_id.as_ref()), None)
                .await
                .map(ops::status::Response::health),
        )
    }

    async fn status_key(
        &self,
        p: ops::status_key::Params,
        ctx: Ctx<'_, '_>,
    ) -> Result<ops::status_key::Response, api::ApiError> {
        let call = Call::new(ctx);
        let health = server(self).status(&call, config_id(p.x_apprise_config_id.as_ref()), Some(p.key.as_str())).await;
        answer(health.map(ops::status_key::Response::health))
    }

    async fn details(
        &self,
        p: ops::details::Params,
        ctx: Ctx<'_, '_>,
    ) -> Result<ops::details::Response, api::ApiError> {
        let call = Call::new(ctx);
        let details = server(self).details(&call, config_id(p.x_apprise_config_id.as_ref()), p.all.as_deref()).await;
        answer(details.map(ops::details::Response::Ok))
    }

    async fn metrics(&self, _: ops::metrics::Params, _: Ctx<'_, '_>) -> Result<ops::metrics::Response, api::ApiError> {
        Ok(ops::metrics::Response::Ok(server(self).metrics_page()))
    }

    async fn notify_stateless(
        &self,
        p: ops::notify_stateless::Params,
        ctx: Ctx<'_, '_>,
    ) -> Result<ops::notify_stateless::Response, api::ApiError> {
        use ops::notify_stateless::Body;
        let call = Call::new(ctx);
        let body = p.body.map(|b| match b {
            Body::Json(j) => NotifyBody::Json(j.0),
            Body::XWwwFormUrlencoded(f) => form_body!(f, |f: &types::StatelessNotificationForm| f.urls.clone()),
            Body::FormData(f) => multipart_body!(f, |f: &types::StatelessNotificationMultipart| f.urls.clone()),
            Body::Plain(t) => NotifyBody::Text { body: t, format: "text" },
            Body::Html(t) => NotifyBody::Text { body: t, format: "html" },
            Body::Markdown(t) => NotifyBody::Text { body: t, format: "markdown" },
        });
        let h = SendHeaders {
            config_id: config_id(p.x_apprise_config_id.as_ref()).map(str::to_owned),
            log_level: p.x_apprise_log_level.map(|l| l.to_string()),
            recursion: p.x_apprise_recursion_count,
            apprise_id: p.x_apprise_id,
        };
        let input = NotifyInput {
            body,
            title: p.x_apprise_title,
            kind: p.x_apprise_type,
            tag: p.x_apprise_tag,
            template: p.x_apprise_template,
            query: p.query.unwrap_or_default(),
        };
        answer(server(self).notify_stateless(&call, h, input).await.map(Into::into))
    }

    async fn notify(&self, p: ops::notify::Params, ctx: Ctx<'_, '_>) -> Result<ops::notify::Response, api::ApiError> {
        use ops::notify::Body;
        let call = Call::new(ctx);
        let body = p.body.map(|b| match b {
            Body::Json(j) => NotifyBody::Json(j.0),
            Body::XWwwFormUrlencoded(f) => form_body!(f, |_: &types::NotificationForm| None),
            Body::FormData(f) => multipart_body!(f, |_: &types::NotificationMultipart| None),
            Body::Plain(t) => NotifyBody::Text { body: t, format: "text" },
            Body::Html(t) => NotifyBody::Text { body: t, format: "html" },
            Body::Markdown(t) => NotifyBody::Text { body: t, format: "markdown" },
        });
        let h = SendHeaders {
            config_id: config_id(p.x_apprise_config_id.as_ref()).map(str::to_owned),
            log_level: p.x_apprise_log_level.map(|l| l.to_string()),
            recursion: p.x_apprise_recursion_count,
            apprise_id: p.x_apprise_id,
        };
        let input = NotifyInput {
            body,
            title: p.x_apprise_title,
            kind: p.x_apprise_type,
            tag: p.x_apprise_tag,
            template: p.x_apprise_template,
            query: p.query.unwrap_or_default(),
        };
        answer(server(self).notify(&call, p.key.as_str(), h, input).await.map(Into::into))
    }

    async fn list_configs(
        &self,
        _: ops::list_configs::Params,
        ctx: Ctx<'_, '_>,
    ) -> Result<ops::list_configs::Response, api::ApiError> {
        use ops::list_configs::{OkBody, Response};
        let call = Call::new(ctx);
        answer(server(self).list(&call).await.map(|l| {
            Response::Ok(match l {
                Listing::Text(t) => OkBody::Plain(t),
                Listing::Json(j) => OkBody::Json(j),
            })
        }))
    }

    async fn config_alias(
        &self,
        p: ops::config_alias::Params,
        ctx: Ctx<'_, '_>,
    ) -> Result<ops::config_alias::Response, api::ApiError> {
        stored!(self, ctx, config_alias, config_id(p.x_apprise_config_id.as_ref()), Some(p.key.as_str()))
    }

    async fn get_config(
        &self,
        p: ops::get_config::Params,
        ctx: Ctx<'_, '_>,
    ) -> Result<ops::get_config::Response, api::ApiError> {
        stored!(self, ctx, get_config, config_id(p.x_apprise_config_id.as_ref()), Some(p.key.as_str()))
    }

    async fn get_config_by_header(
        &self,
        p: ops::get_config_by_header::Params,
        ctx: Ctx<'_, '_>,
    ) -> Result<ops::get_config_by_header::Response, api::ApiError> {
        stored!(self, ctx, get_config_by_header, config_id(p.x_apprise_config_id.as_ref()), None)
    }

    async fn add_config(
        &self,
        p: ops::add_config::Params,
        ctx: Ctx<'_, '_>,
    ) -> Result<ops::add_config::Response, api::ApiError> {
        saved!(self, ctx, add_config, p, Some(p.key.as_str()))
    }

    async fn add_config_by_header(
        &self,
        p: ops::add_config_by_header::Params,
        ctx: Ctx<'_, '_>,
    ) -> Result<ops::add_config_by_header::Response, api::ApiError> {
        saved!(self, ctx, add_config_by_header, p, None)
    }

    async fn delete_config(
        &self,
        p: ops::delete_config::Params,
        ctx: Ctx<'_, '_>,
    ) -> Result<ops::delete_config::Response, api::ApiError> {
        deleted!(self, ctx, delete_config, config_id(p.x_apprise_config_id.as_ref()), Some(p.key.as_str()))
    }

    async fn delete_config_by_header(
        &self,
        p: ops::delete_config_by_header::Params,
        ctx: Ctx<'_, '_>,
    ) -> Result<ops::delete_config_by_header::Response, api::ApiError> {
        deleted!(self, ctx, delete_config_by_header, config_id(p.x_apprise_config_id.as_ref()), None)
    }

    async fn move_config(
        &self,
        p: ops::move_config::Params,
        ctx: Ctx<'_, '_>,
    ) -> Result<ops::move_config::Response, api::ApiError> {
        moved!(self, ctx, move_config, p, Some(p.key.as_str()))
    }

    async fn move_config_by_header(
        &self,
        p: ops::move_config_by_header::Params,
        ctx: Ctx<'_, '_>,
    ) -> Result<ops::move_config_by_header::Response, api::ApiError> {
        moved!(self, ctx, move_config_by_header, p, None)
    }

    async fn get_auth(
        &self,
        p: ops::get_auth::Params,
        ctx: Ctx<'_, '_>,
    ) -> Result<ops::get_auth::Response, api::ApiError> {
        let call = Call::new(ctx);
        answer(
            server(self)
                .get_auth(&call, config_id(p.x_apprise_config_id.as_ref()), Some(p.key.as_str()))
                .await
                .map(ops::get_auth::Response::Ok),
        )
    }

    async fn get_auth_by_header(
        &self,
        p: ops::get_auth_by_header::Params,
        ctx: Ctx<'_, '_>,
    ) -> Result<ops::get_auth_by_header::Response, api::ApiError> {
        let call = Call::new(ctx);
        answer(
            server(self)
                .get_auth(&call, config_id(p.x_apprise_config_id.as_ref()), None)
                .await
                .map(ops::get_auth_by_header::Response::Ok),
        )
    }

    async fn set_auth(
        &self,
        p: ops::set_auth::Params,
        ctx: Ctx<'_, '_>,
    ) -> Result<ops::set_auth::Response, api::ApiError> {
        auth_changed!(
            self,
            ctx,
            set_auth,
            set_auth,
            config_id(p.x_apprise_config_id.as_ref()),
            Some(p.key.as_str()),
            p.body
        )
    }

    async fn set_auth_by_header(
        &self,
        p: ops::set_auth_by_header::Params,
        ctx: Ctx<'_, '_>,
    ) -> Result<ops::set_auth_by_header::Response, api::ApiError> {
        auth_changed!(self, ctx, set_auth_by_header, set_auth, config_id(p.x_apprise_config_id.as_ref()), None, p.body)
    }

    async fn delete_auth(
        &self,
        p: ops::delete_auth::Params,
        ctx: Ctx<'_, '_>,
    ) -> Result<ops::delete_auth::Response, api::ApiError> {
        auth_changed!(
            self,
            ctx,
            delete_auth,
            delete_auth,
            config_id(p.x_apprise_config_id.as_ref()),
            Some(p.key.as_str())
        )
    }

    async fn delete_auth_by_header(
        &self,
        p: ops::delete_auth_by_header::Params,
        ctx: Ctx<'_, '_>,
    ) -> Result<ops::delete_auth_by_header::Response, api::ApiError> {
        auth_changed!(self, ctx, delete_auth_by_header, delete_auth, config_id(p.x_apprise_config_id.as_ref()), None)
    }

    async fn json_urls(
        &self,
        p: ops::json_urls::Params,
        ctx: Ctx<'_, '_>,
    ) -> Result<ops::json_urls::Response, api::ApiError> {
        urls!(self, ctx, json_urls, p, Some(p.key.as_str()))
    }

    async fn json_urls_by_header(
        &self,
        p: ops::json_urls_by_header::Params,
        ctx: Ctx<'_, '_>,
    ) -> Result<ops::json_urls_by_header::Response, api::ApiError> {
        urls!(self, ctx, json_urls_by_header, p, None)
    }
}
