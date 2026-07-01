use std::fmt;

use serde::de::Error;
use serde::{de::Visitor, Deserialize, Deserializer};

#[derive(serde::Deserialize, Debug)]
pub(super) struct DomainJson {
    pub domain: Option<String>,
}

/// The network metadata a MITM-free, DNS-only Web-Shield can attribute per app:
/// the domains it resolved and the destination IPs those resolved to. HTTP /
/// TCP-UDP-port / behavior fields from cuckoo are intentionally absent — they are
/// not observable on Android (see mod.rs).
#[derive(/* serde::Deserialize, - custom */ Debug, Default)]
pub(super) struct NetworkJson {
    pub domains: Option<Vec<DomainJson>>,
    pub hosts: Option<Vec<String>>,
}

#[derive(serde::Deserialize, Debug, Default)]
pub(super) struct HydradragonJson {
    pub network: Option<NetworkJson>,
    /// Full URLs observed live (host + path), for `hydradragon.url`.
    pub urls: Option<Vec<String>>,
    /// On-screen text recognized by the OCR screen-capture pipeline (recent
    /// text for the scanned app, concatenated), for `hydradragon.screen_text`.
    pub screen_text: Option<String>,
}

impl<'de> Deserialize<'de> for NetworkJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct MyVisitor;

        impl<'de> Visitor<'de> for MyVisitor {
            type Value = NetworkJson;

            fn expecting(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt.write_str("string or object")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                // Accept either `domains` (preferred) or the legacy `dns` key for
                // the resolved-domain list; ignore everything else (HTTP, tcp/udp,
                // behavior) since this module no longer exposes it.
                let mut old_domains = None::<serde_json::Value>;
                let mut domains = None::<serde_json::Value>;
                let mut hosts = None::<Vec<String>>;

                while let Some((key, val)) =
                    map.next_entry::<String, serde_json::Value>()?
                {
                    match key.as_str() {
                        "domains" => {
                            domains = Some(val);
                        }
                        "dns" => {
                            if domains.is_some() {
                                continue; // prefer "domains" over "dns"
                            }
                            old_domains = Some(val);
                        }
                        "hosts" if !val.is_null() => {
                            hosts = Some(
                                Deserialize::deserialize(val)
                                    .map_err(Error::custom)?,
                            );
                        }
                        _ => {}
                    }
                }

                #[derive(serde::Deserialize, Debug)]
                struct OldDomainJson {
                    pub hostname: Option<String>,
                }

                let domains: Option<Vec<DomainJson>> =
                    match (domains, old_domains) {
                        (Some(domains), _) if !domains.is_null() => {
                            Deserialize::deserialize(domains)
                                .map_err(Error::custom)?
                        }
                        (None, Some(old_domains))
                            if !old_domains.is_null() =>
                        {
                            let old_domains: Vec<OldDomainJson> =
                                Deserialize::deserialize(old_domains)
                                    .map_err(Error::custom)?;

                            Some(
                                old_domains
                                    .into_iter()
                                    .map(|old| DomainJson {
                                        domain: old.hostname,
                                    })
                                    .collect(),
                            )
                        }
                        _ => None, // domains field is optional or null
                    };

                Ok(NetworkJson { domains, hosts })
            }
        }

        deserializer.deserialize_any(MyVisitor)
    }
}
