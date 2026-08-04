use hydradragonml::features::EngineFeatures;

fn dump(path: &str) {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let feats = match EngineFeatures::extract_from_apk(&bytes) {
        Some(f) => f,
        None => {
            println!("{path}: NO PARSEABLE CONTENT");
            return;
        }
    };
    println!("=== {path} ===");
    println!(
        "classes={:.0} strings={:.0} api={:.0} high={:.0} crit={:.0}",
        feats.dex_class_count, feats.dex_string_count, feats.dex_api_call_count,
        feats.dex_finding_high, feats.dex_finding_critical
    );
    println!(
        "elf={:.0} emulstr={:.0} net={:.0} file={:.0} exec={:.0} adbg={:.0}",
        feats.elf_count, feats.elf_emulated_strings, feats.elf_network_calls,
        feats.elf_file_calls, feats.elf_exec_calls, feats.elf_anti_debug
    );
    println!(
        "danger_perm={:.0} total_perm={:.0} act={:.0} svc={:.0} rcv={:.0} min_sdk={:.0} tgt_sdk={:.0} entropy={:.4}",
        feats.manifest_dangerous_permissions, feats.manifest_total_permissions,
        feats.manifest_activities, feats.manifest_services, feats.manifest_receivers,
        feats.manifest_min_sdk, feats.manifest_target_sdk, feats.entropy
    );
}

fn main() {
    for p in std::env::args().skip(1) {
        dump(&p);
    }
}
