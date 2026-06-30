/*
Port of the Koodous `androguard` YARA module (Apache-2.0, The Koodous Authors)
to YARA-X.

Like the original C module — and like YARA-X's own `cuckoo` module — this does
NOT parse the scanned file. It consumes an external JSON report (the androguard
analysis of an APK) handed to the scanner as module metadata under the key
"androguard", and exposes functions to query it:

    androguard.certificate.issuer(/regex/)
    androguard.certificate.subject(/regex/)
    androguard.certificate.sha1("hex")
    androguard.url(/regex/)            androguard.url("string")
    androguard.app_name(/regex/)       androguard.app_name("string")
    androguard.permission(/regex/)     // permissions + new_permissions
    androguard.activity(/regex/)
    androguard.main_activity(/regex/)
    androguard.service(/regex/)        androguard.service("string")
    androguard.package_name(/regex/)   androguard.package_name("string")
    androguard.min_sdk / max_sdk / target_sdk   // integers
*/

use crate::compiler::RegexId;
use crate::mods::prelude::*;
use crate::modules::protos::androguard::*;

mod schema;

use std::cell::RefCell;
use std::rc::Rc;

thread_local! {
    static LOCAL_DATA: RefCell<Option<Rc<schema::AndroguardJson>>> =
        const { RefCell::new(None) };
}

fn get_local() -> Option<Rc<schema::AndroguardJson>> {
    LOCAL_DATA.with(|data| data.borrow().clone())
}

fn set_local(value: schema::AndroguardJson) {
    LOCAL_DATA.with(|data| {
        *data.borrow_mut() = Some(Rc::new(value));
    });
}

fn main(
    ctx: &mut ModuleContext,
    _data: &[u8],
) -> Result<Androguard, ModuleError> {
    let report = match ctx.get_module_metadata("androguard") {
        None | Some([]) => {
            set_local(schema::AndroguardJson::default());
            return Ok(Androguard::new());
        }
        Some(meta) => match serde_json::from_slice::<schema::AndroguardJson>(meta) {
            Ok(parsed) => parsed,
            Err(e) => {
                set_local(schema::AndroguardJson::default());
                return Err(ModuleError::MetadataError { err: e.to_string() });
            }
        },
    };

    // Mirror the C module_load: surface the SDK versions as integer fields.
    let mut out = Androguard::new();
    if let Some(v) = report.min_sdk_version {
        out.set_min_sdk(v);
    }
    if let Some(v) = report.max_sdk_version {
        out.set_max_sdk(v);
    }
    if let Some(v) = report.target_sdk_version {
        out.set_target_sdk(v);
    }
    // Number of declared permissions (manifest `permissions`).
    out.set_permissions_number(
        report.permissions.as_ref().map(|p| p.len() as i64).unwrap_or(0),
    );

    set_local(report);
    Ok(out)
}

// ── helpers ────────────────────────────────────────────────────────────────

/// 1 if any element of `list` matches the regex, else 0.
#[inline]
fn any_regex(ctx: &ScanContext, regexp_id: RegexId, list: Option<&Vec<String>>) -> i64 {
    match list {
        Some(items) => items
            .iter()
            .any(|s| ctx.regexp_matches(regexp_id, s.as_bytes())) as i64,
        None => 0,
    }
}

/// 1 if any element of `list` equals `needle` (case-insensitive, like the C
/// module's strcasecmp), else 0.
#[inline]
fn any_eqic(list: Option<&Vec<String>>, needle: &str) -> i64 {
    match list {
        Some(items) => items.iter().any(|s| s.eq_ignore_ascii_case(needle)) as i64,
        None => 0,
    }
}

#[inline]
fn one_regex(ctx: &ScanContext, regexp_id: RegexId, value: Option<&String>) -> i64 {
    matches!(value, Some(v) if ctx.regexp_matches(regexp_id, v.as_bytes())) as i64
}

#[inline]
fn one_eqic(value: Option<&String>, needle: &str) -> i64 {
    matches!(value, Some(v) if v.eq_ignore_ascii_case(needle)) as i64
}

// ── certificate.* ──────────────────────────────────────────────────────────

#[module_export(name = "certificate.issuer")]
fn certificate_issuer(ctx: &ScanContext, re: RegexId) -> i64 {
    one_regex(
        ctx,
        re,
        get_local()
            .and_then(|l| l.certificate.as_ref().and_then(|c| c.issuer_dn.clone()))
            .as_ref(),
    )
}

#[module_export(name = "certificate.subject")]
fn certificate_subject(ctx: &ScanContext, re: RegexId) -> i64 {
    one_regex(
        ctx,
        re,
        get_local()
            .and_then(|l| l.certificate.as_ref().and_then(|c| c.subject_dn.clone()))
            .as_ref(),
    )
}

#[module_export(name = "certificate.sha1")]
fn certificate_sha1(ctx: &ScanContext, value: RuntimeString) -> i64 {
    let Ok(needle) = value.to_str(ctx) else {
        return 0;
    };
    one_eqic(
        get_local()
            .and_then(|l| l.certificate.as_ref().and_then(|c| c.sha1.clone()))
            .as_ref(),
        needle,
    )
}

// ── url ────────────────────────────────────────────────────────────────────

#[module_export(name = "url")]
fn url_r(ctx: &ScanContext, re: RegexId) -> i64 {
    any_regex(ctx, re, get_local().and_then(|l| l.urls.clone()).as_ref())
}

#[module_export(name = "url")]
fn url_s(ctx: &ScanContext, value: RuntimeString) -> i64 {
    let Ok(needle) = value.to_str(ctx) else {
        return 0;
    };
    any_eqic(get_local().and_then(|l| l.urls.clone()).as_ref(), needle)
}

// ── app_name ───────────────────────────────────────────────────────────────

#[module_export(name = "app_name")]
fn app_name_r(ctx: &ScanContext, re: RegexId) -> i64 {
    one_regex(ctx, re, get_local().and_then(|l| l.app_name.clone()).as_ref())
}

#[module_export(name = "app_name")]
fn app_name_s(ctx: &ScanContext, value: RuntimeString) -> i64 {
    let Ok(needle) = value.to_str(ctx) else {
        return 0;
    };
    one_eqic(get_local().and_then(|l| l.app_name.clone()).as_ref(), needle)
}

// ── permission (permissions + new_permissions) ─────────────────────────────

#[module_export(name = "permission")]
fn permission_r(ctx: &ScanContext, re: RegexId) -> i64 {
    let local = get_local();
    let a = any_regex(ctx, re, local.as_ref().and_then(|l| l.permissions.as_ref()));
    if a != 0 {
        return 1;
    }
    any_regex(ctx, re, local.as_ref().and_then(|l| l.new_permissions.as_ref()))
}

// ── activity / main_activity ───────────────────────────────────────────────

#[module_export(name = "activity")]
fn activity_r(ctx: &ScanContext, re: RegexId) -> i64 {
    any_regex(ctx, re, get_local().and_then(|l| l.activities.clone()).as_ref())
}

#[module_export(name = "activity")]
fn activity_s(ctx: &ScanContext, value: RuntimeString) -> i64 {
    let Ok(needle) = value.to_str(ctx) else {
        return 0;
    };
    any_eqic(get_local().and_then(|l| l.activities.clone()).as_ref(), needle)
}

// ── receiver (broadcast receivers) ─────────────────────────────────────────

#[module_export(name = "receiver")]
fn receiver_r(ctx: &ScanContext, re: RegexId) -> i64 {
    any_regex(ctx, re, get_local().and_then(|l| l.receivers.clone()).as_ref())
}

#[module_export(name = "receiver")]
fn receiver_s(ctx: &ScanContext, value: RuntimeString) -> i64 {
    let Ok(needle) = value.to_str(ctx) else {
        return 0;
    };
    any_eqic(get_local().and_then(|l| l.receivers.clone()).as_ref(), needle)
}

#[module_export(name = "main_activity")]
fn main_activity_r(ctx: &ScanContext, re: RegexId) -> i64 {
    one_regex(
        ctx,
        re,
        get_local().and_then(|l| l.main_activity.clone()).as_ref(),
    )
}

// ── service ────────────────────────────────────────────────────────────────

#[module_export(name = "service")]
fn service_r(ctx: &ScanContext, re: RegexId) -> i64 {
    any_regex(ctx, re, get_local().and_then(|l| l.services.clone()).as_ref())
}

#[module_export(name = "service")]
fn service_s(ctx: &ScanContext, value: RuntimeString) -> i64 {
    let Ok(needle) = value.to_str(ctx) else {
        return 0;
    };
    any_eqic(get_local().and_then(|l| l.services.clone()).as_ref(), needle)
}

// ── package_name ───────────────────────────────────────────────────────────

#[module_export(name = "package_name")]
fn package_name_r(ctx: &ScanContext, re: RegexId) -> i64 {
    one_regex(
        ctx,
        re,
        get_local().and_then(|l| l.package_name.clone()).as_ref(),
    )
}

#[module_export(name = "package_name")]
fn package_name_s(ctx: &ScanContext, value: RuntimeString) -> i64 {
    let Ok(needle) = value.to_str(ctx) else {
        return 0;
    };
    one_eqic(get_local().and_then(|l| l.package_name.clone()).as_ref(), needle)
}

register_module!("androguard", Androguard, main);
