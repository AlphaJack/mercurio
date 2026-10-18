//! One module per service, discovered by `build.rs`. Do not list modules here.

include!(concat!(env!("OUT_DIR"), "/services_generated.rs"));
