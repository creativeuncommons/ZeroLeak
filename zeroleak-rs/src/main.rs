use std::env;
use zeroleak::ZeroLeak;

fn print_usage() {
    println!("ZeroLeak: Ultra-fast, zero-overhead reversible PII & secrets sanitization engine (Rust)");
    println!("\nUsage:");
    println!("  zeroleak --test <text>          Quick-test masking and roundtrip restitution");
    println!("  zeroleak --list-entities        List all supported entity detectors");
    println!("  zeroleak --print-config         Print active runtime configuration");
    println!("  zeroleak --firewall-test <text> Test prompt injection firewall");
    println!("  zeroleak --help                 Print this help menu");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_usage();
        return;
    }

    let engine = ZeroLeak::default();

    match args[1].as_str() {
        "--help" | "-h" => {
            print_usage();
        }
        "--list-entities" => {
            println!("\nSupported ZeroLeak Entity Detectors (Rust):");
            let mut list: Vec<&String> = engine.enabled_entities.iter().collect();
            list.sort();
            for item in list {
                println!("  • {}", item);
            }
            println!("\nDefault Allowlist (Rust):");
            let mut allows: Vec<&String> = engine.allowlist.iter().collect();
            allows.sort();
            for allow in allows {
                println!("  • {}", allow);
            }
        }
        "--print-config" => {
            println!("\nZeroLeak Runtime Configuration (Rust):");
            println!("  • Version:         0.1.0");
            println!("  • Mode:            {}", engine.mode);
            println!("  • Active Entities: {}", engine.enabled_entities.len());
            println!("  • Allowlist Count: {}", engine.allowlist.len());
            println!("  • Storage:         Ephemeral RAM_ONLY (Zero Disk Writes)");
        }
        "--firewall-test" => {
            if args.len() < 3 {
                eprintln!("Error: --firewall-test requires an input string.");
                return;
            }
            let input = &args[2];
            println!("\nTesting Inter-Agent Prompt Injection Firewall (Rust):");
            println!("Original Input:\n  {}", input);
            let sanitized = engine.sanitize_tool_output(input);
            println!("\nSanitized Output:\n  {}\n", sanitized);
        }
        "--test" => {
            if args.len() < 3 {
                eprintln!("Error: --test requires an input string.");
                return;
            }
            let input = &args[2];
            let trace_id = format!("test_rs_{:x}", rand::random::<u32>());
            println!("\n--- [ZeroLeak Quick-Test (Rust)] (Trace: {}) ---", trace_id);
            println!("Original Plaintext:\n  {}\n", input);

            let masked = engine.mask(input, Some(&trace_id));
            println!("Masked (Safe for LLM Boundary):\n  {}\n", masked);

            let entries = engine.vault.get_session_entries(&trace_id);
            println!("Ephemeral Session Vault ({} tokens captured in RAM):", entries.len());
            for e in &entries {
                println!("  • {} -> {} ({})", e.token, e.raw_value, e.entity_type);
            }

            let restituted = engine.unmask(&masked, &trace_id);
            println!("\nRestituted Plaintext:\n  {}\n", restituted);

            let fidelity = input == &restituted;
            println!("100% Roundtrip Fidelity: {}", if fidelity { "✅ PASS" } else { "❌ FAIL" });

            if let Some(r) = engine.get_audit_receipt(&trace_id) {
                println!("\n=================================================================");
                println!("          ZEROLEAK SECURITY & COMPLIANCE AUDIT RECEIPT (RUST)");
                println!("=================================================================");
                println!(" Trace ID:             {}", r.trace_id);
                println!(" Execution Mode:       {}", r.mode.to_uppercase());
                println!(" Masked Entities:      {}", r.masked_count);
                println!(" Restituted Tokens:    {}", r.restituted_count);
                println!(" Processing Time:      {:.3} ms", r.duration_ms);
                println!(" Ephemeral Storage:    RAM ONLY (Zero Disk Writes)");
                println!("=================================================================\n");
            }
        }
        other => {
            eprintln!("Unknown argument: {}", other);
            print_usage();
        }
    }
}
