//! `hydradragon` — a Suricata/Snort-style network HIPS module.
//!
//! Unlike the cuckoo module it was forked from, this is NOT a sandbox-behavior
//! oracle: the Android Web-Shield is a MITM-free, DNS-only VPN, so the only
//! signals we can actually observe AND attribute to a specific app are:
//!
//!   * the DNS names the app resolves            -> `hydradragon.network.dns_lookup`
//!   * the destination IPs those names resolve to -> `hydradragon.network.host`
//!   * full URLs the app contacts (when known)    -> `hydradragon.url`
//!
//! Everything cuckoo exposed from a Windows sandbox — HTTP method/URI/User-Agent
//! (TLS is encrypted, never seen), arbitrary TCP/UDP destination ports (only
//! port 53 is tunneled), and behavior summaries (mutex/file/registry, no sandbox)
//! — is UNSUPPORTED on Android and has been removed rather than left as dead
//! exports that always return 0. Rules therefore match on the same metadata a
//! DNS-layer HIPS (NextDNS/Pi-hole class) works with: per-app DNS + resolved IP.

use crate::compiler::RegexId;
use crate::mods::prelude::*;
use crate::modules::protos::hydradragon::*;

mod schema;

use std::cell::RefCell;
use std::rc::Rc;
thread_local! {
    static LOCAL_DATA: RefCell<Option<Rc<schema::HydradragonJson>>> = const { RefCell::new(None) };
}

fn get_local() -> Option<Rc<schema::HydradragonJson>> {
    LOCAL_DATA.with(|data| data.borrow().clone())
}

fn set_local(value: schema::HydradragonJson) {
    LOCAL_DATA.with(|data| {
        *data.borrow_mut() = Some(Rc::new(value));
    });
}

fn main(
    _ctx: &mut ModuleContext,
    _data: &[u8],
) -> Result<Hydradragon, ModuleError> {
    let meta = match _ctx.get_module_metadata("hydradragon") {
        None | Some([]) => {
            set_local(schema::HydradragonJson::default());
            return Ok(Hydradragon::new());
        }
        Some(meta) => meta,
    };

    match serde_json::from_slice::<schema::HydradragonJson>(meta) {
        Ok(parsed) => {
            set_local(parsed);
        }
        Err(e) => {
            set_local(schema::HydradragonJson::default());
            return Err(ModuleError::MetadataError { err: e.to_string() });
        }
    };

    Ok(Hydradragon::new())
}

/// Number of DNS lookups the app made whose resolved domain matches the given
/// regular expression (0 if none). The core per-app HIPS signal.
#[module_export(name = "network.dns_lookup")]
fn network_dns_lookup_r(ctx: &ScanContext, regexp_id: RegexId) -> i64 {
    get_local()
        .as_ref()
        .and_then(|local| local.network.as_ref())
        .and_then(|network| network.domains.as_ref())
        .map(|domains| {
            domains
                .iter()
                .filter(|domain| {
                    matches!(&domain.domain, Some(domain_domain) if ctx.regexp_matches(regexp_id, domain_domain.as_bytes()))
                })
                .count() as i64
        })
        .unwrap_or(0)
}

/// Number of destination IPs the app's DNS resolved to that match the given
/// regular expression (0 if none). This is the Snort/Suricata "dst host" check —
/// e.g. `hydradragon.network.host(/^203\.0\.113\./)` for a known-bad /24.
#[module_export(name = "network.host")]
fn network_host_r(ctx: &ScanContext, re: RegexId) -> i64 {
    get_local()
        .as_ref()
        .and_then(|local| local.network.as_ref())
        .and_then(|network| network.hosts.as_ref())
        .map(|hosts| {
            hosts
                .iter()
                .filter(|host| ctx.regexp_matches(re, host.as_bytes()))
                .count() as i64
        })
        .unwrap_or(0)
}

/// Number of full URLs (host + path) the app contacted that match the given
/// regular expression. Android-native; fed when a full URL is known.
#[module_export(name = "url")]
fn url_r(ctx: &ScanContext, re: RegexId) -> i64 {
    get_local()
        .and_then(|l| l.urls.clone())
        .map(|urls| {
            urls.iter()
                .filter(|u| ctx.regexp_matches(re, u.as_bytes()))
                .count() as i64
        })
        .unwrap_or(0)
}

/// Number of full URLs the app contacted equal (case-insensitive) to the given
/// string.
#[module_export(name = "url")]
fn url_s(ctx: &ScanContext, value: RuntimeString) -> i64 {
    let Ok(needle) = value.to_str(ctx) else {
        return 0;
    };
    get_local()
        .and_then(|l| l.urls.clone())
        .map(|urls| urls.iter().filter(|u| u.eq_ignore_ascii_case(needle)).count() as i64)
        .unwrap_or(0)
}

register_module!("hydradragon", Hydradragon, main);
