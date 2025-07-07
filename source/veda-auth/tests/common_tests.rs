use veda_auth::common::*;
use v_individual_model::onto::individual::Individual;
use v_individual_model::onto::datatype::Lang;
use v_common::module::ticket::Ticket;
use v_storage::{VStorage, StorageId, StorageMode};
use chrono::Utc;
use std::collections::HashMap;

#[test]
fn test_set_password_creates_hash_and_salt() {
    let mut credential = Individual::default();
    let password = "test_password_123";
    
    // Call function from the project
    veda_auth::common::set_password(&mut credential, password);
    
    // Check that the password was hashed
    let stored_password = credential.get_first_literal("v-s:password").unwrap();
    let stored_salt = credential.get_first_literal("v-s:salt").unwrap();
    
    assert!(!stored_password.is_empty());
    assert!(!stored_salt.is_empty());
    assert_ne!(stored_password, password); // Password should be hashed
    assert_eq!(stored_salt.len(), 128); // Salt should be 64 bytes in hex = 128 characters
    assert_eq!(stored_password.len(), 128); // Hash should be 64 bytes in hex = 128 characters
}

#[test]
fn test_set_password_different_passwords_different_hashes() {
    let mut credential1 = Individual::default();
    let mut credential2 = Individual::default();
    
    // Call function from the project for different passwords
    veda_auth::common::set_password(&mut credential1, "password1");
    veda_auth::common::set_password(&mut credential2, "password2");
    
    let hash1 = credential1.get_first_literal("v-s:password").unwrap();
    let hash2 = credential2.get_first_literal("v-s:password").unwrap();
    let salt1 = credential1.get_first_literal("v-s:salt").unwrap();
    let salt2 = credential2.get_first_literal("v-s:salt").unwrap();
    
    // Different passwords should give different hashes and salts
    assert_ne!(hash1, hash2);
    assert_ne!(salt1, salt2);
}

#[test]
fn test_auth_conf_default_values() {
    // Call function from the project
    let conf = AuthConf::default();
    
    // Check default values
    assert_eq!(conf.failed_auth_attempts, 2);
    assert_eq!(conf.failed_change_pass_attempts, 2);
    assert_eq!(conf.failed_auth_lock_period, 30 * 60); // 30 minutes
    assert_eq!(conf.ticket_lifetime, 10 * 60 * 60); // 10 hours
    assert_eq!(conf.pass_lifetime, 90 * 24 * 60 * 60); // 90 days
    assert_eq!(conf.check_ticket_ip, true);
}

#[test]
fn test_user_stat_default() {
    // Call function from the project
    let user_stat = UserStat::default();
    
    // Check initial values
    assert_eq!(user_stat.wrong_count_login, 0);
    assert_eq!(user_stat.last_wrong_login_date, 0);
    assert_eq!(user_stat.attempt_change_pass, 0);
    assert_eq!(user_stat.last_attempt_change_pass_date, 0);
}

#[test]
fn test_create_new_ticket_with_valid_data() {
    // Create temporary in-memory storage
    let storage_box = VStorage::builder()
        .memory()
        .build()
        .expect("Failed to create memory storage");
    let mut storage = VStorage::new(storage_box);
    
    let login = "test_user";
    let user_id = "test:user123";
    let addr = "127.0.0.1";
    let duration = 3600; // 1 hour
    let mut ticket = Ticket::default();
    
    // Call function from the project
    veda_auth::common::create_new_ticket(login, user_id, addr, duration, &mut ticket, &mut storage);
    
    // Check that ticket was created correctly
    assert_eq!(ticket.user_login, login);
    assert_eq!(ticket.user_uri, user_id);
    assert_eq!(ticket.user_addr, addr);
    assert!(!ticket.id.is_empty());
    assert!(ticket.start_time > 0);
    assert!(ticket.end_time > ticket.start_time);
    assert_eq!(ticket.result, v_common::v_api::common_type::ResultCode::Ok);
}

#[test]
fn test_create_new_ticket_with_invalid_ip() {
    let storage_box = VStorage::builder()
        .memory()
        .build()
        .expect("Failed to create memory storage");
    let mut storage = VStorage::new(storage_box);
    
    let login = "test_user";
    let user_id = "test:user123";
    let invalid_addr = "invalid_ip_address";
    let duration = 3600;
    let mut ticket = Ticket::default();
    
    // Call function from the project with invalid IP
    veda_auth::common::create_new_ticket(login, user_id, invalid_addr, duration, &mut ticket, &mut storage);
    
    // Ticket should not be created due to invalid IP
    assert!(ticket.id.is_empty());
}

#[test]
fn test_create_sys_ticket() {
    let storage_box = VStorage::builder()
        .memory()
        .build()
        .expect("Failed to create memory storage");
    let mut storage = VStorage::new(storage_box);
    
    // Call function from the project
    let sys_ticket = veda_auth::common::create_sys_ticket(&mut storage);
    
    // Check that system ticket was created
    assert_eq!(sys_ticket.user_login, "veda");
    assert_eq!(sys_ticket.user_uri, "cfg:VedaSystem");
    assert_eq!(sys_ticket.user_addr, "127.0.0.1");
    assert!(!sys_ticket.id.is_empty());
    assert_eq!(sys_ticket.result, v_common::v_api::common_type::ResultCode::Ok);
}

#[test]
fn test_read_duration_param() {
    let mut individual = Individual::default();
    
    // Set duration parameter
    individual.set_string("test_duration", "1h 30m", Lang::none());
    
    // Call function from the project
    let duration = veda_auth::common::read_duration_param(&mut individual, "test_duration");
    
    // Check that duration was parsed correctly
    assert!(duration.is_some());
    let duration = duration.unwrap();
    assert_eq!(duration.as_secs(), 5400); // 1.5 hours = 5400 seconds
}

#[test]
fn test_read_duration_param_invalid() {
    let mut individual = Individual::default();
    
    // Set invalid parameter
    individual.set_string("test_duration", "invalid_duration", Lang::none());
    
    // Call function from the project
    let duration = veda_auth::common::read_duration_param(&mut individual, "test_duration");
    
    // Should return None for invalid format
    assert!(duration.is_none());
}

#[test]
fn test_read_duration_param_missing() {
    let mut individual = Individual::default();
    
    // Don't set parameter
    
    // Call function from the project
    let duration = veda_auth::common::read_duration_param(&mut individual, "missing_param");
    
    // Should return None for missing parameter
    assert!(duration.is_none());
}

#[cfg(test)]
mod tests_with_constants {
    use super::*;
    
    #[test]
    fn test_constants_are_defined() {
        // Check constants from the project
        assert_eq!(veda_auth::common::EMPTY_SHA256_HASH, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(veda_auth::common::ALLOW_TRUSTED_GROUP, "cfg:TrustedAuthenticationUserGroup");
        assert_eq!(veda_auth::common::N_ITER, 100_000);
        assert_eq!(veda_auth::common::TICKS_TO_UNIX_EPOCH, 62_135_596_800_000);
    }
} 