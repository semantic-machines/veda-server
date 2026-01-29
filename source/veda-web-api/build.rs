use std::fs;

fn main() {
    // Read Cargo.toml to extract v_common features
    let cargo_toml = fs::read_to_string("Cargo.toml").expect("Failed to read Cargo.toml");
    
    let mut v_common_features = String::new();
    
    for line in cargo_toml.lines() {
        // Find line with v_common dependency
        if line.contains("v_common") && line.contains("features") {
            // Extract features array from the line
            if let Some(start) = line.find("features = [") {
                let rest = &line[start + 12..];
                if let Some(end) = rest.find(']') {
                    let features_str = &rest[..end];
                    // Parse features: remove quotes and spaces
                    let features: Vec<&str> = features_str
                        .split(',')
                        .map(|s| s.trim().trim_matches('"'))
                        .filter(|s| !s.is_empty())
                        .collect();
                    v_common_features = features.join(", ");
                }
            }
        }
    }
    
    println!("cargo:rustc-env=V_COMMON_FEATURES={}", v_common_features);
    println!("cargo:rerun-if-changed=Cargo.toml");
}
