use regex::Regex;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntityMatch {
    pub start: usize,
    pub end: usize,
    pub entity_type: String,
    pub raw_value: String,
}

pub fn luhn_checksum(number_str: &str) -> bool {
    let digits: Vec<u32> = number_str
        .chars()
        .filter_map(|c| c.to_digit(10))
        .collect();

    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }

    let mut checksum = 0;
    for (i, &d) in digits.iter().rev().enumerate() {
        let mut val = d;
        if i % 2 == 1 {
            val *= 2;
            if val > 9 {
                val -= 9;
            }
        }
        checksum += val;
    }
    checksum % 10 == 0
}

pub fn shannon_entropy(data: &str) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = HashMap::new();
    for c in data.chars() {
        *counts.entry(c).or_insert(0usize) += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in counts.values() {
        let p = (count as f64) / len;
        entropy -= p * p.log2();
    }
    entropy
}

pub fn is_valid_ipv4(ip: &str) -> bool {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    for p in parts {
        if p.len() > 1 && p.starts_with('0') {
            return false;
        }
        match p.parse::<u16>() {
            Ok(v) if v <= 255 => continue,
            _ => return false,
        }
    }
    true
}

pub struct EntityPatterns {
    pub email: Regex,
    pub phone: Regex,
    pub ssn: Regex,
    pub credit_card: Regex,
    pub ip_address: Regex,
    pub api_key: Regex,
    pub bearer: Regex,
    pub jwt: Regex,
    pub crypto: Regex,
    pub secret_candidate: Regex,
}

impl Default for EntityPatterns {
    fn default() -> Self {
        Self {
            email: Regex::new(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}\b").unwrap(),
            phone: Regex::new(r"(?:\+?1[-.\s]?)?\(?([2-9]\d{2})\)?[-.\s]?([2-9]\d{2})[-.\s]?(\d{4})\b").unwrap(),
            ssn: Regex::new(r"\b(?!000|666|9\d{2})(\d{3})-(?!00)(\d{2})-(?!0000)(\d{4})\b").unwrap(),
            credit_card: Regex::new(r"\b(?:\d{4}[-\s]?){3}\d{1,7}\b|\b\d{13,19}\b").unwrap(),
            ip_address: Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b").unwrap(),
            api_key: Regex::new(r"\bAKIA[0-9A-Z]{16}\b|\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}\b|\bgithub_pat_[A-Za-z0-9_]{82}\b|\bsk-[a-zA-Z0-9_-]{20,}\b|\bsk-proj-[a-zA-Z0-9_-]{40,}\b|\b[sr]k_(?:live|test)_[0-9a-zA-Z]{24,32}\b|\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*\b|\bAIza[0-9A-Za-z\-_]{35}\b|\bsk-ant-[a-zA-Z0-9_-]{20,}\b").unwrap(),
            bearer: Regex::new(r"(?i)\bBearer\s+([A-Za-z0-9\-._~+/]+=*)").unwrap(),
            jwt: Regex::new(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{10,}\b").unwrap(),
            crypto: Regex::new(r"\b0x[a-fA-F0-9]{40}\b|\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|\bbc1[a-z0-9]{39,59}\b").unwrap(),
            secret_candidate: Regex::new(r"\b[A-Za-z0-9_\-]{24,128}\b").unwrap(),
        }
    }
}

impl EntityPatterns {
    pub fn scan(
        &self,
        text: &str,
        enabled_entities: &HashSet<String>,
        allowlist: &HashSet<String>,
    ) -> Vec<EntityMatch> {
        let is_allowed = |val: &str, etype: &str| -> bool {
            if allowlist.is_empty() {
                return false;
            }
            if matches!(etype, "API_KEY" | "BEARER_TOKEN" | "JWT" | "CRYPTO_KEY" | "PRIVATE_KEY") {
                return false;
            }
            let lowered = val.trim().to_lowercase();
            if etype == "EMAIL" {
                if let Some((_, dom)) = lowered.rsplit_once('@') {
                    return allowlist.iter().any(|a| !a.is_empty() && (lowered == *a || dom == *a || dom.ends_with(&format!(".{}", a))));
                }
            }
            allowlist.iter().any(|a| !a.is_empty() && lowered == *a)
        };

        let mut matches = Vec::new();

        // 1. Email
        if enabled_entities.contains("EMAIL") {
            for m in self.email.find_iter(text) {
                let val = m.as_str();
                if !is_allowed(val, "EMAIL") {
                    matches.push(EntityMatch {
                        start: m.start(),
                        end: m.end(),
                        entity_type: "EMAIL".to_string(),
                        raw_value: val.to_string(),
                    });
                }
            }
        }

        // 2. Phone
        if enabled_entities.contains("PHONE_US") {
            for m in self.phone.find_iter(text) {
                let val = m.as_str();
                if !is_allowed(val, "PHONE") {
                    matches.push(EntityMatch {
                        start: m.start(),
                        end: m.end(),
                        entity_type: "PHONE".to_string(),
                        raw_value: val.to_string(),
                    });
                }
            }
        }

        // 3. SSN
        if enabled_entities.contains("SSN") {
            for m in self.ssn.find_iter(text) {
                let val = m.as_str();
                if !is_allowed(val, "SSN") {
                    matches.push(EntityMatch {
                        start: m.start(),
                        end: m.end(),
                        entity_type: "SSN".to_string(),
                        raw_value: val.to_string(),
                    });
                }
            }
        }

        // 4. Credit Card (Luhn checked)
        if enabled_entities.contains("CREDIT_CARD") {
            for m in self.credit_card.find_iter(text) {
                let val = m.as_str();
                let digits: String = val.chars().filter(|c| c.is_ascii_digit()).collect();
                if (13..=19).contains(&digits.len()) && luhn_checksum(&digits) && !is_allowed(val, "CREDIT_CARD") {
                    matches.push(EntityMatch {
                        start: m.start(),
                        end: m.end(),
                        entity_type: "CREDIT_CARD".to_string(),
                        raw_value: val.to_string(),
                    });
                }
            }
        }

        // 5. IP Address
        if enabled_entities.contains("IP_ADDRESS") {
            for m in self.ip_address.find_iter(text) {
                let val = m.as_str();
                if val.contains('.') && !is_valid_ipv4(val) {
                    continue;
                }
                if !is_allowed(val, "IP_ADDRESS") {
                    matches.push(EntityMatch {
                        start: m.start(),
                        end: m.end(),
                        entity_type: "IP_ADDRESS".to_string(),
                        raw_value: val.to_string(),
                    });
                }
            }
        }

        // 6. Known API Keys
        if enabled_entities.contains("API_KEY_HIGH_ENTROPY") {
            for m in self.api_key.find_iter(text) {
                let val = m.as_str();
                if !is_allowed(val, "API_KEY") {
                    matches.push(EntityMatch {
                        start: m.start(),
                        end: m.end(),
                        entity_type: "API_KEY".to_string(),
                        raw_value: val.to_string(),
                    });
                }
            }
        }

        // 7. Bearer Token
        if enabled_entities.contains("BEARER_TOKEN") {
            for caps in self.bearer.captures_iter(text) {
                if let Some(m) = caps.get(1) {
                    let val = m.as_str();
                    if val.len() >= 16 && !is_allowed(val, "BEARER_TOKEN") {
                        matches.push(EntityMatch {
                            start: m.start(),
                            end: m.end(),
                            entity_type: "BEARER_TOKEN".to_string(),
                            raw_value: val.to_string(),
                        });
                    }
                }
            }
        }

        // 8. JWT
        if enabled_entities.contains("JWT") {
            for m in self.jwt.find_iter(text) {
                let val = m.as_str();
                if !is_allowed(val, "JWT") {
                    matches.push(EntityMatch {
                        start: m.start(),
                        end: m.end(),
                        entity_type: "JWT".to_string(),
                        raw_value: val.to_string(),
                    });
                }
            }
        }

        // 9. Crypto Wallet
        if enabled_entities.contains("CRYPTO_WALLET") {
            for m in self.crypto.find_iter(text) {
                let val = m.as_str();
                if !is_allowed(val, "CRYPTO_KEY") {
                    matches.push(EntityMatch {
                        start: m.start(),
                        end: m.end(),
                        entity_type: "CRYPTO_KEY".to_string(),
                        raw_value: val.to_string(),
                    });
                }
            }
        }

        // 10. Generic High-Entropy Secret Candidates
        if enabled_entities.contains("API_KEY_HIGH_ENTROPY") {
            for m in self.secret_candidate.find_iter(text) {
                let val = m.as_str();
                if val.len() >= 30 && shannon_entropy(val) >= 3.3 && !is_allowed(val, "API_KEY") {
                    matches.push(EntityMatch {
                        start: m.start(),
                        end: m.end(),
                        entity_type: "API_KEY".to_string(),
                        raw_value: val.to_string(),
                    });
                }
            }
        }

        // Deduplicate & sort: start ascending, length descending
        matches.sort_by(|a, b| a.start.cmp(&b.start).then_with(|| (b.end - b.start).cmp(&(a.end - a.start))));

        let mut filtered: Vec<EntityMatch> = Vec::new();
        let mut last_end = 0;
        for m in matches {
            if m.start >= last_end {
                last_end = m.end;
                filtered.push(m);
            }
        }

        filtered
    }
}
