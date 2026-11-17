use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultEntry {
    pub token: String,
    pub raw_value: String,
    pub entity_type: String,
    pub trace_id: String,
    pub access_count: usize,
}

pub struct SessionVault {
    salt: [u8; 32],
    default_ttl: Duration,
    inner: RwLock<VaultInner>,
}

struct VaultInner {
    // trace_id -> { token -> VaultEntry }
    token_map: HashMap<String, HashMap<String, VaultEntry>>,
    // trace_id -> { salted_hash -> token }
    hash_map: HashMap<String, HashMap<String, String>>,
    // trace_id -> { entity_type -> counter }
    counters: HashMap<String, HashMap<String, usize>>,
    // trace_id -> creation Instant
    session_created: HashMap<String, Instant>,
}

impl SessionVault {
    pub fn new(default_ttl_secs: u64) -> Self {
        let mut salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut salt);
        Self {
            salt,
            default_ttl: Duration::from_secs(default_ttl_secs),
            inner: RwLock::new(VaultInner {
                token_map: HashMap::new(),
                hash_map: HashMap::new(),
                counters: HashMap::new(),
                session_created: HashMap::new(),
            }),
        }
    }

    fn hash_value(&self, raw: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(&self.salt);
        hasher.update(raw.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    pub fn cleanup_expired(&self) -> usize {
        let mut inner = self.inner.write().unwrap();
        let now = Instant::now();
        let ttl = self.default_ttl;

        let expired: Vec<String> = inner
            .session_created
            .iter()
            .filter(|(_, &created)| now.duration_since(created) > ttl)
            .map(|(tid, _)| tid.clone())
            .collect();

        let count = expired.len();
        for tid in expired {
            inner.token_map.remove(&tid);
            inner.hash_map.remove(&tid);
            inner.counters.remove(&tid);
            inner.session_created.remove(&tid);
        }
        count
    }

    pub fn get_or_create_token(&self, trace_id: &str, raw_value: &str, entity_type: &str) -> String {
        self.cleanup_expired();
        let hashed = self.hash_value(raw_value);

        let mut inner = self.inner.write().unwrap();

        // 1. Check existing
        let existing_token = inner.hash_map.get(trace_id).and_then(|h| h.get(&hashed).cloned());
        if let Some(token) = existing_token {
            if let Some(session_tokens) = inner.token_map.get_mut(trace_id) {
                if let Some(entry) = session_tokens.get_mut(&token) {
                    entry.access_count += 1;
                    return entry.token.clone();
                }
            }
        }

        // 2. Initialize session if missing
        if !inner.session_created.contains_key(trace_id) {
            inner.session_created.insert(trace_id.to_string(), Instant::now());
            inner.token_map.insert(trace_id.to_string(), HashMap::new());
            inner.hash_map.insert(trace_id.to_string(), HashMap::new());
            inner.counters.insert(trace_id.to_string(), HashMap::new());
        }

        // 3. Increment counter and construct token
        let session_counters = inner.counters.get_mut(trace_id).unwrap();
        let counter = session_counters.entry(entity_type.to_string()).or_insert(0);
        *counter += 1;
        let token = format!("[{}_{}]", entity_type, counter);

        let entry = VaultEntry {
            token: token.clone(),
            raw_value: raw_value.to_string(),
            entity_type: entity_type.to_string(),
            trace_id: trace_id.to_string(),
            access_count: 1,
        };

        inner.token_map.get_mut(trace_id).unwrap().insert(token.clone(), entry);
        inner.hash_map.get_mut(trace_id).unwrap().insert(hashed, token.clone());

        token
    }

    pub fn resolve_token(&self, trace_id: &str, token: &str) -> Option<String> {
        let inner = self.inner.read().unwrap();
        inner
            .token_map
            .get(trace_id)
            .and_then(|m| m.get(token))
            .map(|e| e.raw_value.clone())
    }

    pub fn get_session_entries(&self, trace_id: &str) -> Vec<VaultEntry> {
        let inner = self.inner.read().unwrap();
        inner
            .token_map
            .get(trace_id)
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default()
    }

    pub fn purge(&self, trace_id: &str) -> bool {
        let mut inner = self.inner.write().unwrap();
        let r1 = inner.token_map.remove(trace_id).is_some();
        inner.hash_map.remove(trace_id);
        inner.counters.remove(trace_id);
        inner.session_created.remove(trace_id);
        r1
    }
}
