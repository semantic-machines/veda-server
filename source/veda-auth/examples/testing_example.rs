use veda_auth::*;
use v_individual_model::onto::individual::Individual;
use v_individual_model::onto::datatype::Lang;
use v_storage::VStorage;
use v_common::module::ticket::Ticket;
use v_common::v_api::common_type::ResultCode;
use chrono::Utc;

/// Testing examples for veda-auth
/// 
/// This example shows how to write tests for authentication functionality
/// and demonstrates testing patterns and best practices.
fn main() {
    println!("=== Veda Auth Testing Examples ===");
    
    // Run various test scenarios
    test_password_security();
    test_authentication_flow();
    test_user_statistics();
    test_configuration_scenarios();
    test_edge_cases();
    
    println!("\n=== All tests completed ===");
}

/// Test password security features
fn test_password_security() {
    println!("\n1. Testing password security...");
    
    // Test password hashing consistency
    let mut cred1 = Individual::default();
    let mut cred2 = Individual::default();
    
    let password = "TestPassword123!";
    set_password(&mut cred1, password);
    set_password(&mut cred2, password);
    
    let hash1 = cred1.get_first_literal("v-s:password").unwrap();
    let hash2 = cred2.get_first_literal("v-s:password").unwrap();
    let salt1 = cred1.get_first_literal("v-s:salt").unwrap();
    let salt2 = cred2.get_first_literal("v-s:salt").unwrap();
    
    assert_ne!(hash1, hash2, "Same password should produce different hashes");
    assert_ne!(salt1, salt2, "Each password should have unique salt");
    assert_eq!(hash1.len(), 128, "Hash should be 128 hex characters");
    assert_eq!(salt1.len(), 128, "Salt should be 128 hex characters");
    
    println!("✓ Password hashing security verified");
    
    // Test different password types
    let long_password = "A".repeat(1000);
    let test_passwords = vec![
        ("empty", ""),
        ("simple", "password"),
        ("complex", "Complex123!@#"),
        ("unicode", "Пароль123фёё"),
        ("emoji", "🔐🛡️🔒"),
        ("long", &long_password),
    ];
    
    for (name, pwd) in test_passwords {
        let mut cred = Individual::default();
        set_password(&mut cred, pwd);
        
        let hash = cred.get_first_literal("v-s:password").unwrap();
        assert_eq!(hash.len(), 128, "Hash length should be consistent for {}", name);
        
        println!("✓ {} password handled correctly", name);
    }
}

/// Test authentication flow
fn test_authentication_flow() {
    println!("\n2. Testing authentication flow...");
    
    let storage_box = VStorage::builder().memory().build().unwrap();
    let mut storage = VStorage::new(storage_box);
    
    // Create system ticket
    let sys_ticket = create_sys_ticket(&mut storage);
    assert_eq!(sys_ticket.result, ResultCode::Ok);
    assert!(!sys_ticket.id.is_empty());
    assert_eq!(sys_ticket.user_uri, "cfg:VedaSystem");
    println!("✓ System ticket creation");
    
    // Create user tickets with different parameters
    let test_cases = vec![
        ("admin", "user:admin", "127.0.0.1", 3600),
        ("user1", "user:123", "192.168.1.1", 7200),
        ("guest", "user:guest", "10.0.0.1", 1800),
    ];
    
    for (login, user_id, ip, lifetime) in test_cases {
        let mut ticket = Ticket::default();
        create_new_ticket(login, user_id, ip, lifetime, &mut ticket, &mut storage);
        
        assert_eq!(ticket.result, ResultCode::Ok);
        assert_eq!(ticket.user_login, login);
        assert_eq!(ticket.user_uri, user_id);
        assert!(!ticket.id.is_empty());
        
        let expected_duration = (ticket.end_time - ticket.start_time) / 10_000_000;
        assert_eq!(expected_duration, lifetime);
        
        println!("✓ Ticket created for {} ({})", login, user_id);
    }
}

/// Test user statistics and locking
fn test_user_statistics() {
    println!("\n3. Testing user statistics and locking...");
    
    let config = AuthConf::default();
    let now = Utc::now().timestamp();
    
    // Test normal user (not locked)
    let normal_user = UserStat {
        wrong_count_login: 1,
        last_wrong_login_date: now - 1800, // 30 minutes ago
        attempt_change_pass: 0,
        last_attempt_change_pass_date: 0,
    };
    
    let should_lock = should_lock_user(&normal_user, &config);
    assert!(!should_lock, "Normal user should not be locked");
    println!("✓ Normal user not locked");
    
    // Test locked user (too many attempts)
    let locked_user = UserStat {
        wrong_count_login: 5,
        last_wrong_login_date: now - 60, // 1 minute ago
        attempt_change_pass: 0,
        last_attempt_change_pass_date: 0,
    };
    
    let should_lock = should_lock_user(&locked_user, &config);
    assert!(should_lock, "User with too many attempts should be locked");
    println!("✓ User with failed attempts locked");
    
    // Test expired lock
    let expired_lock_user = UserStat {
        wrong_count_login: 5,
        last_wrong_login_date: now - 3600, // 1 hour ago
        attempt_change_pass: 0,
        last_attempt_change_pass_date: 0,
    };
    
    let should_lock = should_lock_user(&expired_lock_user, &config);
    assert!(!should_lock, "Expired lock should not prevent access");
    println!("✓ Expired lock properly handled");
}

/// Test different configuration scenarios
fn test_configuration_scenarios() {
    println!("\n4. Testing configuration scenarios...");
    
    // Test default configuration
    let default_config = AuthConf::default();
    assert_eq!(default_config.failed_auth_attempts, 2);
    assert_eq!(default_config.ticket_lifetime, 10 * 60 * 60);
    assert!(default_config.check_ticket_ip);
    println!("✓ Default configuration");
    
    // Test custom configurations
    let strict_config = AuthConf {
        failed_auth_attempts: 1,
        failed_change_pass_attempts: 1,
        failed_auth_lock_period: 60 * 60, // 1 hour
        ticket_lifetime: 30 * 60, // 30 minutes
        check_ticket_ip: true,
        ..Default::default()
    };
    
    let relaxed_config = AuthConf {
        failed_auth_attempts: 10,
        failed_change_pass_attempts: 5,
        failed_auth_lock_period: 60, // 1 minute
        ticket_lifetime: 24 * 60 * 60, // 24 hours
        check_ticket_ip: false,
        ..Default::default()
    };
    
    println!("✓ Strict configuration: {} max attempts", strict_config.failed_auth_attempts);
    println!("✓ Relaxed configuration: {} max attempts", relaxed_config.failed_auth_attempts);
}

/// Test edge cases and error conditions
fn test_edge_cases() {
    println!("\n5. Testing edge cases...");
    
    // Test empty values
    let mut empty_cred = Individual::default();
    set_password(&mut empty_cred, "");
    assert!(empty_cred.get_first_literal("v-s:password").is_some());
    println!("✓ Empty password handled");
    
    // Test very long values
    let long_password = "A".repeat(10000);
    let mut long_cred = Individual::default();
    set_password(&mut long_cred, &long_password);
    let hash = long_cred.get_first_literal("v-s:password").unwrap();
    assert_eq!(hash.len(), 128); // Should still be 128 chars
    println!("✓ Very long password handled");
    
    // Test special characters
    let special_chars = "!@#$%^&*()_+-=[]{}|;':\",./<>?`~";
    let mut special_cred = Individual::default();
    set_password(&mut special_cred, special_chars);
    assert!(special_cred.get_first_literal("v-s:password").is_some());
    println!("✓ Special characters handled");
    
    // Test ticket creation edge cases
    let storage_box = VStorage::builder().memory().build().unwrap();
    let mut storage = VStorage::new(storage_box);
    
    // Test zero lifetime
    let mut zero_ticket = Ticket::default();
    create_new_ticket("test", "user:test", "127.0.0.1", 0, &mut zero_ticket, &mut storage);
    assert_eq!(zero_ticket.result, ResultCode::Ok);
    println!("✓ Zero lifetime ticket handled");
    
    // Test negative lifetime
    let mut neg_ticket = Ticket::default();
    create_new_ticket("test", "user:test", "127.0.0.1", -3600, &mut neg_ticket, &mut storage);
    assert_eq!(neg_ticket.result, ResultCode::Ok);
    println!("✓ Negative lifetime ticket handled");
}

/// Helper function to check if user should be locked
fn should_lock_user(user_stat: &UserStat, config: &AuthConf) -> bool {
    let now = Utc::now().timestamp();
    
    // Check auth lock
    if user_stat.wrong_count_login >= config.failed_auth_attempts {
        if now - user_stat.last_wrong_login_date < config.failed_auth_lock_period {
            return true;
        }
    }
    
    // Check password change lock
    if user_stat.attempt_change_pass >= config.failed_change_pass_attempts {
        if now - user_stat.last_attempt_change_pass_date < config.failed_pass_change_lock_period {
            return true;
        }
    }
    
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_password_hashing() {
        let mut cred = Individual::default();
        set_password(&mut cred, "test_password");
        
        let hash = cred.get_first_literal("v-s:password").unwrap();
        let salt = cred.get_first_literal("v-s:salt").unwrap();
        
        assert_eq!(hash.len(), 128);
        assert_eq!(salt.len(), 128);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(salt.chars().all(|c| c.is_ascii_hexdigit()));
    }
    
    #[test]
    fn test_different_passwords_different_hashes() {
        let mut cred1 = Individual::default();
        let mut cred2 = Individual::default();
        
        set_password(&mut cred1, "password1");
        set_password(&mut cred2, "password2");
        
        let hash1 = cred1.get_first_literal("v-s:password").unwrap();
        let hash2 = cred2.get_first_literal("v-s:password").unwrap();
        
        assert_ne!(hash1, hash2);
    }
    
    #[test]
    fn test_same_password_different_hashes() {
        let mut cred1 = Individual::default();
        let mut cred2 = Individual::default();
        
        set_password(&mut cred1, "same_password");
        set_password(&mut cred2, "same_password");
        
        let hash1 = cred1.get_first_literal("v-s:password").unwrap();
        let hash2 = cred2.get_first_literal("v-s:password").unwrap();
        
        // Should be different due to different salts
        assert_ne!(hash1, hash2);
    }
    
    #[test]
    fn test_user_locking_logic() {
        let config = AuthConf::default();
        let now = Utc::now().timestamp();
        
        // Test user that should be locked
        let locked_user = UserStat {
            wrong_count_login: 3,
            last_wrong_login_date: now - 60,
            attempt_change_pass: 0,
            last_attempt_change_pass_date: 0,
        };
        
        assert!(should_lock_user(&locked_user, &config));
        
        // Test user that should not be locked
        let normal_user = UserStat {
            wrong_count_login: 1,
            last_wrong_login_date: now - 60,
            attempt_change_pass: 0,
            last_attempt_change_pass_date: 0,
        };
        
        assert!(!should_lock_user(&normal_user, &config));
    }
    
    #[test]
    fn test_ticket_creation_different_lifetimes() {
        let storage_box = VStorage::builder().memory().build().unwrap();
        let mut storage = VStorage::new(storage_box);
        
        let lifetimes = vec![60, 3600, 86400];
        
        for lifetime in lifetimes {
            let mut ticket = Ticket::default();
            create_new_ticket("test", "user:test", "127.0.0.1", lifetime, &mut ticket, &mut storage);
            
            assert_eq!(ticket.result, ResultCode::Ok);
            let actual_lifetime = (ticket.end_time - ticket.start_time) / 10_000_000;
            assert_eq!(actual_lifetime, lifetime);
        }
    }
} 