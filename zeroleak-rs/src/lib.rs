pub mod detectors;
pub mod firewall;
pub mod vault;

use detectors::{EntityPatterns, luhn_checksum, shannon_entropy};
use firewall::PromptInjectionFirewall;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::Instant;
pub use vault::{SessionVault, VaultEntry};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReceipt {
    pub trace_id: String,
    pub mode: String,
    pub masked_count: usize,
    pub restituted_count: usize,
    pub types_detected: HashMap<String, usize>,
    pub advisories: Vec<String>,
    pub duration_ms: f64,
    pub zero_disk_leakage: bool,
}

pub struct ZeroLeak {
    pub mode: String,
    pub enabled_entities: HashSet<String>,
    pub allowlist: HashSet<String>,
    pub vault: Arc<SessionVault>,
    patterns: EntityPatterns,
    firewall: PromptInjectionFirewall,
    receipts: RwLock<HashMap<String, AuditReceipt>>,
}

impl Default for ZeroLeak {
    fn default() -> Self {
        Self::new("enforce", None, None, 1800)
    }
}

impl ZeroLeak {
    pub fn new(
        mode: &str,
        enabled_entities: Option<Vec<String>>,
        allowlist: Option<Vec<String>>,
        vault_ttl_secs: u64,
    ) -> Self {
        let default_entities = vec![
            "EMAIL",
            "PHONE_US",
            "SSN",
            "CREDIT_CARD",
            "IP_ADDRESS",
            "API_KEY_HIGH_ENTROPY",
            "BEARER_TOKEN",
            "JWT",
            "CRYPTO_WALLET",
        ];

        let default_allowlist = vec![
            "localhost",
            "127.0.0.1",
            "::1",
            "example.com",
            "test.com",
            "schema.org",
            "w3.org",
        ];

        let entities: HashSet<String> = enabled_entities
            .unwrap_or_else(|| default_entities.into_iter().map(String::from).collect())
            .into_iter()
            .collect();

        let allowed: HashSet<String> = allowlist
            .unwrap_or_else(|| default_allowlist.into_iter().map(String::from).collect())
            .into_iter()
            .map(|s| s.to_lowercase())
            .collect();

        Self {
            mode: mode.to_string(),
            enabled_entities: entities,
            allowlist: allowed,
            vault: Arc::new(SessionVault::new(vault_ttl_secs)),
            patterns: EntityPatterns::default(),
            firewall: PromptInjectionFirewall::default(),
            receipts: RwLock::new(HashMap::new()),
        }
    }

    pub fn mask(&self, text: &str, trace_id: Option<&str>) -> String {
        let t0 = Instant::now();
        let tid = trace_id
            .map(String::from)
            .unwrap_or_else(|| format!("trc_{:x}", rand::random::<u64>()));

        let matches = self
            .patterns
            .scan(text, &self.enabled_entities, &self.allowlist);

        let mut types_detected: HashMap<String, usize> = HashMap::new();
        let mut advisories = Vec::new();

        if matches.is_empty() {
            let receipt = AuditReceipt {
                trace_id: tid.clone(),
                mode: self.mode.clone(),
                masked_count: 0,
                restituted_count: 0,
                types_detected,
                advisories,
                duration_ms: t0.elapsed().as_secs_f64() * 1000.0,
                zero_disk_leakage: true,
            };
            self.receipts.write().unwrap().insert(tid, receipt);
            return text.to_string();
        }

        if self.mode == "observe" {
            for m in &matches {
                *types_detected.entry(m.entity_type.clone()).or_insert(0) += 1;
                advisories.push(format!(
                    "[ZeroLeak OBSERVE] Would mask {}: '{}'",
                    m.entity_type,
                    if m.raw_value.len() > 6 {
                        format!("{}...{}", &m.raw_value[..3], &m.raw_value[m.raw_value.len() - 3..])
                    } else {
                        "***".to_string()
                    }
                ));
            }
            let receipt = AuditReceipt {
                trace_id: tid.clone(),
                mode: self.mode.clone(),
                masked_count: 0,
                restituted_count: 0,
                types_detected,
                advisories,
                duration_ms: t0.elapsed().as_secs_f64() * 1000.0,
                zero_disk_leakage: true,
            };
            self.receipts.write().unwrap().insert(tid, receipt);
            return text.to_string();
        }

        // Enforce mode: rebuild text with synthetic tokens
        let mut result = String::with_capacity(text.len());
        let mut last_idx = 0;

        for m in &matches {
            *types_detected.entry(m.entity_type.clone()).or_insert(0) += 1;
            result.push_str(&text[last_idx..m.start]);
            let token = self.vault.get_or_create_token(&tid, &m.raw_value, &m.entity_type);
            result.push_str(&token);
            last_idx = m.end;
        }
        result.push_str(&text[last_idx..]);

        let receipt = AuditReceipt {
            trace_id: tid.clone(),
            mode: self.mode.clone(),
            masked_count: matches.len(),
            restituted_count: 0,
            types_detected,
            advisories,
            duration_ms: t0.elapsed().as_secs_f64() * 1000.0,
            zero_disk_leakage: true,
        };
        self.receipts.write().unwrap().insert(tid, receipt);

        result
    }

    pub fn unmask(&self, text: &str, trace_id: &str) -> String {
        let t0 = Instant::now();
        let entries = self.vault.get_session_entries(trace_id);
        if entries.is_empty() {
            return text.to_string();
        }

        let mut sorted_entries = entries;
        sorted_entries.sort_by(|a, b| b.token.len().cmp(&a.token.len()));

        let mut restituted = text.to_string();
        let mut restituted_count = 0;

        for entry in sorted_entries {
            if restituted.contains(&entry.token) {
                let count = restituted.matches(&entry.token).count();
                restituted = restituted.replace(&entry.token, &entry.raw_value);
                restituted_count += count;
            }
        }

        if let Some(r) = self.receipts.write().unwrap().get_mut(trace_id) {
            r.restituted_count += restituted_count;
            r.duration_ms += t0.elapsed().as_secs_f64() * 1000.0;
        }

        restituted
    }

    pub fn sanitize_tool_output(&self, text: &str) -> String {
        self.firewall.sanitize(text)
    }

    pub fn get_audit_receipt(&self, trace_id: &str) -> Option<AuditReceipt> {
        self.receipts.read().unwrap().get(trace_id).cloned()
    }
}
