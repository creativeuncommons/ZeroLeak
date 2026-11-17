use regex::Regex;

pub struct PromptInjectionFirewall {
    patterns: Vec<Regex>,
}

impl Default for PromptInjectionFirewall {
    fn default() -> Self {
        Self {
            patterns: vec![
                Regex::new(r"(?i)\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior)\s+(?:instructions|prompts|directives)\b").unwrap(),
                Regex::new(r"(?i)\b(?:system\s+directive|developer\s+mode|dan\s+mode)\b").unwrap(),
                Regex::new(r"(?i)<\|im_start\|>|<\|im_end\|>|\[INST\]|\[/INST\]").unwrap(),
                Regex::new(r"(?i)\b(?:you\s+are\s+now|act\s+as\s+an?\s+unrestricted)\b").unwrap(),
                Regex::new(r"!\[[^\]]{0,512}\]\(\s*https?://[^\s)]{1,2048}\)").unwrap(),
                Regex::new(r"[\u{200b}-\u{200f}\u{feff}]").unwrap(),
                Regex::new(r"\x1b\[[0-9;]*[a-zA-Z]").unwrap(),
            ],
        }
    }
}

impl PromptInjectionFirewall {
    pub fn sanitize(&self, content: &str) -> String {
        let mut result = content.to_string();
        for pat in &self.patterns {
            result = pat.replace_all(&result, "[DEFANGED_INJECTION]").into_owned();
        }
        result
    }
}
