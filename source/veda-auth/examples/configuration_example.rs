use veda_auth::{AuthConf, UserStat};
use chrono::Utc;

/// Example showing how to configure authentication settings
/// 
/// This example demonstrates various configuration options
/// available in the veda-auth system.
pub struct ConfigExample;

impl ConfigExample {
    /// Create default configuration
    pub fn create_default_config() -> AuthConf {
        AuthConf::default()
    }
    
    /// Create production configuration with strict security settings
    pub fn create_production_config() -> AuthConf {
        AuthConf {
            // Security settings
            failed_auth_attempts: 3,           // Allow 3 failed attempts
            failed_change_pass_attempts: 2,    // Allow 2 failed password change attempts
            failed_auth_lock_period: 15 * 60,  // Lock for 15 minutes after failed attempts
            failed_pass_change_lock_period: 30 * 60, // Lock for 30 minutes after failed password changes
            success_pass_change_lock_period: 24 * 60 * 60, // Wait 24 hours between password changes
            
            // Ticket settings
            ticket_lifetime: 8 * 60 * 60,      // 8 hours ticket lifetime
            secret_lifetime: 6 * 60 * 60,      // 6 hours secret code lifetime
            pass_lifetime: 60 * 24 * 60 * 60,  // 60 days password lifetime
            
            // Email notification templates
            expired_pass_notification_template: Some((
                "expired_password_template".to_string(),
                "Your password has expired. Use secret code: {{secret}}".to_string()
            )),
            denied_password_expired_notification_template: Some((
                "denied_password_change_template".to_string(),
                "Password change is not allowed for your account type.".to_string()
            )),
            
            // Network settings
            check_ticket_ip: true,              // Enforce IP checking for tickets
        }
    }
    
    /// Create development configuration with relaxed settings
    pub fn create_development_config() -> AuthConf {
        AuthConf {
            // Relaxed security for development
            failed_auth_attempts: 10,          // Allow more failed attempts
            failed_change_pass_attempts: 5,    // Allow more password change attempts
            failed_auth_lock_period: 5 * 60,   // Short lock period (5 minutes)
            failed_pass_change_lock_period: 10 * 60, // Short password change lock (10 minutes)
            success_pass_change_lock_period: 60,     // Allow frequent password changes (1 minute)
            
            // Extended lifetimes for development
            ticket_lifetime: 24 * 60 * 60,     // 24 hours ticket lifetime
            secret_lifetime: 24 * 60 * 60,     // 24 hours secret code lifetime
            pass_lifetime: 0,                  // No password expiration
            
            // No email notifications in development
            expired_pass_notification_template: None,
            denied_password_expired_notification_template: None,
            
            // Relaxed network settings
            check_ticket_ip: false,             // Don't enforce IP checking
        }
    }
    
    /// Create high-security configuration for sensitive environments
    pub fn create_high_security_config() -> AuthConf {
        AuthConf {
            // Very strict security
            failed_auth_attempts: 2,           // Allow only 2 failed attempts
            failed_change_pass_attempts: 1,    // Allow only 1 failed password change
            failed_auth_lock_period: 60 * 60,  // Lock for 1 hour after failed attempts
            failed_pass_change_lock_period: 2 * 60 * 60, // Lock for 2 hours after failed password changes
            success_pass_change_lock_period: 7 * 24 * 60 * 60, // Wait 7 days between password changes
            
            // Short lifetimes for maximum security
            ticket_lifetime: 2 * 60 * 60,      // 2 hours ticket lifetime
            secret_lifetime: 30 * 60,          // 30 minutes secret code lifetime
            pass_lifetime: 30 * 24 * 60 * 60,  // 30 days password lifetime
            
            // Email notifications enabled
            expired_pass_notification_template: Some((
                "security_expired_password_template".to_string(),
                "SECURITY ALERT: Your password has expired. Use secret code: {{secret}}".to_string()
            )),
            denied_password_expired_notification_template: Some((
                "security_denied_password_change_template".to_string(),
                "SECURITY ALERT: Password change denied for your account type.".to_string()
            )),
            
            // Strict network settings
            check_ticket_ip: true,              // Enforce strict IP checking
        }
    }
    
    /// Create configuration for testing
    pub fn create_test_config() -> AuthConf {
        AuthConf {
            // Settings suitable for automated testing
            failed_auth_attempts: 1000,        // Allow many attempts for testing
            failed_change_pass_attempts: 1000, // Allow many password changes
            failed_auth_lock_period: 1,        // Very short lock period
            failed_pass_change_lock_period: 1, // Very short password change lock
            success_pass_change_lock_period: 1, // Allow immediate password changes
            
            // Short lifetimes for quick testing
            ticket_lifetime: 60,               // 1 minute ticket lifetime
            secret_lifetime: 60,               // 1 minute secret code lifetime
            pass_lifetime: 0,                  // No password expiration
            
            // No email notifications in tests
            expired_pass_notification_template: None,
            denied_password_expired_notification_template: None,
            
            // Relaxed network settings for testing
            check_ticket_ip: false,             // Don't enforce IP checking in tests
        }
    }
    
    /// Print configuration summary
    pub fn print_config_summary(config: &AuthConf) {
        println!("=== Authentication Configuration Summary ===");
        println!("Failed auth attempts allowed: {}", config.failed_auth_attempts);
        println!("Failed password change attempts allowed: {}", config.failed_change_pass_attempts);
        println!("Auth lock period: {} seconds", config.failed_auth_lock_period);
        println!("Password change lock period: {} seconds", config.failed_pass_change_lock_period);
        println!("Success password change lock period: {} seconds", config.success_pass_change_lock_period);
        println!("Ticket lifetime: {} seconds", config.ticket_lifetime);
        println!("Secret code lifetime: {} seconds", config.secret_lifetime);
        println!("Password lifetime: {} seconds", config.pass_lifetime);
        println!("Check ticket IP: {}", config.check_ticket_ip);
        println!("Has expired password notification: {}", config.expired_pass_notification_template.is_some());
        println!("Has denied password change notification: {}", config.denied_password_expired_notification_template.is_some());
        println!("==========================================");
    }
    
    /// Example of user statistics tracking
    pub fn create_user_stats_example() -> UserStat {
        let now = Utc::now().timestamp();
        
        UserStat {
            wrong_count_login: 2,               // 2 failed login attempts
            last_wrong_login_date: now - 300,  // Last failed attempt 5 minutes ago
            attempt_change_pass: 1,             // 1 password change attempt
            last_attempt_change_pass_date: now - 3600, // Last password change attempt 1 hour ago
        }
    }
    
    /// Check if user should be locked based on statistics
    pub fn should_lock_user(user_stat: &UserStat, config: &AuthConf) -> bool {
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
}

fn main() {
    println!("=== Veda Auth Configuration Examples ===\n");
    
    // Example 1: Default configuration
    println!("1. Default Configuration:");
    let default_config = ConfigExample::create_default_config();
    ConfigExample::print_config_summary(&default_config);
    
    // Example 2: Production configuration
    println!("\n2. Production Configuration:");
    let prod_config = ConfigExample::create_production_config();
    ConfigExample::print_config_summary(&prod_config);
    
    // Example 3: Development configuration
    println!("\n3. Development Configuration:");
    let dev_config = ConfigExample::create_development_config();
    ConfigExample::print_config_summary(&dev_config);
    
    // Example 4: High security configuration
    println!("\n4. High Security Configuration:");
    let security_config = ConfigExample::create_high_security_config();
    ConfigExample::print_config_summary(&security_config);
    
    // Example 5: Test configuration
    println!("\n5. Test Configuration:");
    let test_config = ConfigExample::create_test_config();
    ConfigExample::print_config_summary(&test_config);
    
    // Example 6: User statistics
    println!("\n6. User Statistics Example:");
    let user_stat = ConfigExample::create_user_stats_example();
    println!("User statistics: {:?}", user_stat);
    
    // Check if user should be locked
    let should_lock = ConfigExample::should_lock_user(&user_stat, &prod_config);
    println!("Should lock user (production config): {}", should_lock);
    
    let should_lock_dev = ConfigExample::should_lock_user(&user_stat, &dev_config);
    println!("Should lock user (development config): {}", should_lock_dev);
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_config_creation() {
        let config = ConfigExample::create_default_config();
        assert_eq!(config.failed_auth_attempts, 2);
        assert_eq!(config.ticket_lifetime, 10 * 60 * 60);
    }
    
    #[test]
    fn test_production_config() {
        let config = ConfigExample::create_production_config();
        assert_eq!(config.failed_auth_attempts, 3);
        assert_eq!(config.ticket_lifetime, 8 * 60 * 60);
        assert!(config.check_ticket_ip);
    }
    
    #[test]
    fn test_development_config() {
        let config = ConfigExample::create_development_config();
        assert_eq!(config.failed_auth_attempts, 10);
        assert_eq!(config.pass_lifetime, 0);
        assert!(!config.check_ticket_ip);
    }
    
    #[test]
    fn test_user_lock_logic() {
        let config = ConfigExample::create_production_config();
        let user_stat = ConfigExample::create_user_stats_example();
        
        // Should not lock with current settings
        assert!(!ConfigExample::should_lock_user(&user_stat, &config));
        
        // Create a user that should be locked
        let mut locked_user = user_stat;
        locked_user.wrong_count_login = 5;
        locked_user.last_wrong_login_date = Utc::now().timestamp() - 60; // 1 minute ago
        
        assert!(ConfigExample::should_lock_user(&locked_user, &config));
    }
} 