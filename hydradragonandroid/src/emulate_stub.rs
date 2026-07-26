/// No-op stubs for host builds (non-Android) so cargo test works
/// without unicorn-engine-sys / bindgen / VS headers.

pub fn probe_emulation() -> bool { false }
pub fn host_arch() -> &'static str { "host" }
pub fn unsupported_reason() -> &'static str { "not available on host" }

#[derive(Clone, Debug)]
pub struct ApiCall {
    pub name: String,
}

#[derive(Clone, Debug, Default)]
pub struct EmulationResult {
    pub strings: Vec<String>,
    pub api_calls: Vec<ApiCall>,
}

pub fn emulate(_so_bytes: &[u8]) -> EmulationResult {
    EmulationResult::default()
}
