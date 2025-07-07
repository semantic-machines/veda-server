use veda_auth::*;
use v_individual_model::onto::individual::Individual;
use v_individual_model::onto::datatype::Lang;
use v_common::module::ticket::Ticket;
use v_storage::VStorage;
use v_common::v_api::common_type::ResultCode;

/// Basic usage examples for veda-auth
/// 
/// This example demonstrates the core functionality:
/// - Creating credentials
/// - Setting passwords
/// - Creating tickets
/// - Password verification
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Veda Auth Basic Usage Examples ===\n");
    
    // Create in-memory storage for examples
    let storage_box = VStorage::builder()
        .memory()
        .build()?;
    let mut storage = VStorage::new(storage_box);
    
    // Example 1: Create system ticket
    println!("1. Creating system ticket...");
    let sys_ticket = create_sys_ticket(&mut storage);
    println!("✓ System ticket created: {}", sys_ticket.id);
    
    // Example 2: Create and set password
    println!("\n2. Creating credential and setting password...");
    let mut credential = Individual::default();
    credential.set_id("credential:example");
    
    let password = "MySecurePassword123!";
    set_password(&mut credential, password);
    
    let stored_password = credential.get_first_literal("v-s:password").unwrap();
    let stored_salt = credential.get_first_literal("v-s:salt").unwrap();
    
    println!("✓ Password set successfully");
    println!("  - Password hash length: {}", stored_password.len());
    println!("  - Salt length: {}", stored_salt.len());
    
    // Example 3: Create user ticket
    println!("\n3. Creating user ticket...");
    let mut user_ticket = Ticket::default();
    let login = "admin";
    let user_id = "user:admin";
    let addr = "127.0.0.1";
    let lifetime = 3600; // 1 hour
    
    create_new_ticket(login, user_id, addr, lifetime, &mut user_ticket, &mut storage);
    
    if user_ticket.result == ResultCode::Ok {
        println!("✓ User ticket created successfully");
        println!("  - Ticket ID: {}", user_ticket.id);
        println!("  - User URI: {}", user_ticket.user_uri);
        println!("  - User login: {}", user_ticket.user_login);
        println!("  - Valid until: {}", user_ticket.end_time);
    } else {
        println!("✗ Failed to create user ticket: {:?}", user_ticket.result);
    }
    
    // Example 4: Configuration examples
    println!("\n4. Configuration examples...");
    let default_config = AuthConf::default();
    println!("✓ Default configuration:");
    println!("  - Failed auth attempts: {}", default_config.failed_auth_attempts);
    println!("  - Ticket lifetime: {} seconds", default_config.ticket_lifetime);
    println!("  - Password lifetime: {} seconds", default_config.pass_lifetime);
    
    // Example 5: User statistics
    println!("\n5. User statistics example...");
    let mut user_stat = UserStat::default();
    user_stat.wrong_count_login = 2;
    user_stat.last_wrong_login_date = chrono::Utc::now().timestamp() - 300; // 5 minutes ago
    
    println!("✓ User statistics:");
    println!("  - Wrong login count: {}", user_stat.wrong_count_login);
    println!("  - Last wrong login: {} seconds ago", 
             chrono::Utc::now().timestamp() - user_stat.last_wrong_login_date);
    
    // Example 6: Check if user should be locked
    println!("\n6. User locking logic...");
    let should_lock = user_stat.wrong_count_login >= default_config.failed_auth_attempts &&
                     chrono::Utc::now().timestamp() - user_stat.last_wrong_login_date < default_config.failed_auth_lock_period;
    
    if should_lock {
        println!("⚠ User should be locked due to failed attempts");
    } else {
        println!("✓ User is not locked");
    }
    
    // Example 7: Working with different password types
    println!("\n7. Password handling examples...");
    
    // Test with different password types
    let long_password = "A".repeat(100); // Very long password
    let passwords = vec![
        "simple",
        "Complex123!",
        "Пароль123",
        "🔐🛡️🔒",
        &long_password,
        "", // Empty password
    ];
    
    for (i, pwd) in passwords.iter().enumerate() {
        let mut cred = Individual::default();
        cred.set_id(&format!("credential:test{}", i));
        set_password(&mut cred, pwd);
        
        let hash = cred.get_first_literal("v-s:password").unwrap();
        println!("  - Password {} chars → hash {} chars", pwd.len(), hash.len());
    }
    
    // Example 8: Constants demonstration
    println!("\n8. Authentication constants...");
    println!("  - Empty SHA256 hash: {}", EMPTY_SHA256_HASH);
    println!("  - Trusted group: {}", ALLOW_TRUSTED_GROUP);
    println!("  - PBKDF2 iterations: {}", N_ITER);
    println!("  - Ticks to Unix epoch: {}", TICKS_TO_UNIX_EPOCH);
    
    println!("\n=== Basic Usage Examples Complete ===");
    Ok(())
}

/// Demonstrate password verification simulation
fn demonstrate_password_verification() {
    println!("\n=== Password Verification Demo ===");
    
    // Create a credential with password
    let mut credential = Individual::default();
    let original_password = "TestPassword123!";
    set_password(&mut credential, original_password);
    
    // Simulate password verification process
    let stored_password = credential.get_first_literal("v-s:password").unwrap();
    let stored_salt = credential.get_first_literal("v-s:salt").unwrap();
    
    println!("✓ Credential created with password");
    println!("  - Stored password hash: {}...", &stored_password[..20]);
    println!("  - Stored salt: {}...", &stored_salt[..20]);
    
    // In real implementation, this would use the verification logic from AuthWorkPlace
    println!("  - Password verification would check against stored hash");
    println!("  - Using PBKDF2 with {} iterations", N_ITER);
}

/// Show different configuration scenarios
fn show_configuration_scenarios() {
    println!("\n=== Configuration Scenarios ===");
    
    // High security environment
    let high_security = AuthConf {
        failed_auth_attempts: 2,
        failed_change_pass_attempts: 1,
        failed_auth_lock_period: 30 * 60,      // 30 minutes
        failed_pass_change_lock_period: 60 * 60, // 1 hour
        success_pass_change_lock_period: 24 * 60 * 60, // 24 hours
        ticket_lifetime: 2 * 60 * 60,          // 2 hours
        secret_lifetime: 30 * 60,              // 30 minutes
        pass_lifetime: 30 * 24 * 60 * 60,      // 30 days
        expired_pass_notification_template: Some((
            "security_template".to_string(),
            "Security alert: password expired".to_string()
        )),
        denied_password_expired_notification_template: Some((
            "denied_template".to_string(),
            "Password change denied".to_string()
        )),
        check_ticket_ip: true,
    };
    
    println!("High Security Configuration:");
    println!("  - Max failed attempts: {}", high_security.failed_auth_attempts);
    println!("  - Ticket lifetime: {} hours", high_security.ticket_lifetime / 3600);
    println!("  - Password lifetime: {} days", high_security.pass_lifetime / (24 * 60 * 60));
    
    // Development environment
    let dev_config = AuthConf {
        failed_auth_attempts: 100,
        failed_change_pass_attempts: 100,
        failed_auth_lock_period: 1,
        failed_pass_change_lock_period: 1,
        success_pass_change_lock_period: 1,
        ticket_lifetime: 24 * 60 * 60,         // 24 hours
        secret_lifetime: 24 * 60 * 60,         // 24 hours
        pass_lifetime: 0,                      // No expiration
        expired_pass_notification_template: None,
        denied_password_expired_notification_template: None,
        check_ticket_ip: false,
    };
    
    println!("\nDevelopment Configuration:");
    println!("  - Max failed attempts: {}", dev_config.failed_auth_attempts);
    println!("  - Ticket lifetime: {} hours", dev_config.ticket_lifetime / 3600);
    println!("  - Password lifetime: {} (no expiration)", dev_config.pass_lifetime);
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_basic_password_setting() {
        let mut credential = Individual::default();
        credential.set_id("test:credential");
        
        set_password(&mut credential, "test_password");
        
        let stored_password = credential.get_first_literal("v-s:password");
        let stored_salt = credential.get_first_literal("v-s:salt");
        
        assert!(stored_password.is_some());
        assert!(stored_salt.is_some());
        
        let password = stored_password.unwrap();
        let salt = stored_salt.unwrap();
        
        assert_eq!(password.len(), 128); // SHA512 hex = 128 chars
        assert_eq!(salt.len(), 128);     // SHA512 hex = 128 chars
    }
    
    #[test]
    fn test_ticket_creation() {
        let storage_box = VStorage::builder().memory().build().unwrap();
        let mut storage = VStorage::new(storage_box);
        
        let mut ticket = Ticket::default();
        create_new_ticket("test_user", "user:test", "127.0.0.1", 3600, &mut ticket, &mut storage);
        
        assert_eq!(ticket.result, ResultCode::Ok);
        assert_eq!(ticket.user_login, "test_user");
        assert_eq!(ticket.user_uri, "user:test");
        assert!(!ticket.id.is_empty());
    }
    
    #[test]
    fn test_system_ticket_creation() {
        let storage_box = VStorage::builder().memory().build().unwrap();
        let mut storage = VStorage::new(storage_box);
        
        let sys_ticket = create_sys_ticket(&mut storage);
        
        assert_eq!(sys_ticket.result, ResultCode::Ok);
        assert!(!sys_ticket.id.is_empty());
        assert_eq!(sys_ticket.user_uri, "cfg:VedaSystem");
    }
    
    #[test]
    fn test_config_defaults() {
        let config = AuthConf::default();
        
        assert_eq!(config.failed_auth_attempts, 2);
        assert_eq!(config.ticket_lifetime, 10 * 60 * 60);
        assert_eq!(config.pass_lifetime, 90 * 24 * 60 * 60);
        assert!(config.check_ticket_ip);
    }
    
    #[test]
    fn test_user_stat_defaults() {
        let user_stat = UserStat::default();
        
        assert_eq!(user_stat.wrong_count_login, 0);
        assert_eq!(user_stat.last_wrong_login_date, 0);
        assert_eq!(user_stat.attempt_change_pass, 0);
        assert_eq!(user_stat.last_attempt_change_pass_date, 0);
    }
} 