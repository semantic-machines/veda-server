use veda_auth::*;
use v_individual_model::onto::individual::Individual;
use v_individual_model::onto::datatype::Lang;
use v_common::module::ticket::Ticket;
use v_storage::{VStorage, StorageId, StorageMode};
use v_common::v_api::common_type::ResultCode;
use chrono::Utc;
use std::time::Duration;

#[test]
fn test_password_workflow() {
    // Create object to store account data
    let mut credential = Individual::default();
    credential.set_id("test:credential");
    
    let original_password = "MySecurePassword123!";
    
    // Call function from the project to set password
    veda_auth::set_password(&mut credential, original_password);
    
    // Check that password was set and hashed
    let stored_password = credential.get_first_literal("v-s:password");
    let stored_salt = credential.get_first_literal("v-s:salt");
    
    assert!(stored_password.is_some());
    assert!(stored_salt.is_some());
    
    let stored_password = stored_password.unwrap();
    let stored_salt = stored_salt.unwrap();
    
    // Password should be hash, not original text
    assert_ne!(stored_password, original_password);
    assert!(!stored_password.is_empty());
    assert!(!stored_salt.is_empty());
    
    // Check hash format (should be hex string of specific length)
    assert_eq!(stored_password.len(), 128); // SHA512 = 64 bytes = 128 hex characters
    assert_eq!(stored_salt.len(), 128);
    
    // Check that hash contains only hex characters
    assert!(stored_password.chars().all(|c| c.is_ascii_hexdigit()));
    assert!(stored_salt.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_ticket_creation_workflow() {
    // Create temporary storage
    let storage_box = VStorage::builder()
        .memory()
        .build()
        .expect("Failed to create memory storage");
    let mut storage = VStorage::new(storage_box);
    
    // Test data
    let login = "test_user";
    let user_id = "test:user123";
    let addr = "192.168.1.1";
    let duration = 7200; // 2 hours
    
    let mut ticket = Ticket::default();
    
    // Call function from the project to create ticket
    veda_auth::create_new_ticket(login, user_id, addr, duration, &mut ticket, &mut storage);
    
    // Check result
    assert_eq!(ticket.result, ResultCode::Ok);
    assert_eq!(ticket.user_login, login);
    assert_eq!(ticket.user_uri, user_id);
    assert_eq!(ticket.user_addr, addr);
    assert!(!ticket.id.is_empty());
    
    // Check timestamps
    assert!(ticket.start_time > 0);
    assert!(ticket.end_time > ticket.start_time);
    
    // Check that time difference matches specified duration
    let actual_duration = (ticket.end_time - ticket.start_time) / 10_000_000; // Convert to seconds
    assert_eq!(actual_duration, duration);
}

#[test]
fn test_system_ticket_creation() {
    let storage_box = VStorage::builder()
        .memory()
        .build()
        .expect("Failed to create memory storage");
    let mut storage = VStorage::new(storage_box);
    
    // Call function from the project to create system ticket
    let sys_ticket = veda_auth::create_sys_ticket(&mut storage);
    
    // Check that system ticket was created correctly
    assert_eq!(sys_ticket.result, ResultCode::Ok);
    assert_eq!(sys_ticket.user_login, "veda");
    assert_eq!(sys_ticket.user_uri, "cfg:VedaSystem");
    assert_eq!(sys_ticket.user_addr, "127.0.0.1");
    assert!(!sys_ticket.id.is_empty());
    
    // Check that ticket has long duration (system ticket)
    let duration = (sys_ticket.end_time - sys_ticket.start_time) / 10_000_000;
    assert_eq!(duration, 90_000_000); // 90 million seconds
}

#[test]
fn test_multiple_tickets_have_unique_ids() {
    let storage_box = VStorage::builder()
        .memory()
        .build()
        .expect("Failed to create memory storage");
    let mut storage = VStorage::new(storage_box);
    
    let mut ticket1 = Ticket::default();
    let mut ticket2 = Ticket::default();
    
    // Create two tickets with same parameters
    veda_auth::create_new_ticket("user1", "test:user1", "127.0.0.1", 3600, &mut ticket1, &mut storage);
    veda_auth::create_new_ticket("user1", "test:user1", "127.0.0.1", 3600, &mut ticket2, &mut storage);
    
    // Check that tickets have different IDs
    assert_ne!(ticket1.id, ticket2.id);
    assert!(!ticket1.id.is_empty());
    assert!(!ticket2.id.is_empty());
}

#[test]
fn test_invalid_ip_address_handling() {
    let storage_box = VStorage::builder()
        .memory()
        .build()
        .expect("Failed to create memory storage");
    let mut storage = VStorage::new(storage_box);
    
    let mut ticket = Ticket::default();
    
    // Try to create ticket with invalid IP address
    veda_auth::create_new_ticket("user1", "test:user1", "invalid_ip", 3600, &mut ticket, &mut storage);
    
    // Ticket should not be created
    assert!(ticket.id.is_empty());
    assert_ne!(ticket.result, ResultCode::Ok);
}

#[test]
fn test_auth_configuration_constants() {
    // Check project constants
    assert_eq!(veda_auth::EMPTY_SHA256_HASH, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assert_eq!(veda_auth::ALLOW_TRUSTED_GROUP, "cfg:TrustedAuthenticationUserGroup");
    assert_eq!(veda_auth::N_ITER, 100_000);
    assert_eq!(veda_auth::TICKS_TO_UNIX_EPOCH, 62_135_596_800_000);
}

#[test]
fn test_auth_conf_default_configuration() {
    // Call function from the project to create default configuration
    let conf = AuthConf::default();
    
    // Check all configuration fields
    assert_eq!(conf.failed_auth_attempts, 2);
    assert_eq!(conf.failed_change_pass_attempts, 2);
    assert_eq!(conf.failed_auth_lock_period, 1800); // 30 minutes
    assert_eq!(conf.failed_pass_change_lock_period, 1800); // 30 minutes
    assert_eq!(conf.success_pass_change_lock_period, 86400); // 24 hours
    assert_eq!(conf.ticket_lifetime, 36000); // 10 hours
    assert_eq!(conf.secret_lifetime, 43200); // 12 hours
    assert_eq!(conf.pass_lifetime, 7776000); // 90 days
    assert_eq!(conf.check_ticket_ip, true);
    assert!(conf.expired_pass_notification_template.is_none());
    assert!(conf.denied_password_expired_notification_template.is_none());
}

#[test]
fn test_user_stat_initialization() {
    // Call function from the project to create user statistics
    let user_stat = UserStat::default();
    
    // Check initial values
    assert_eq!(user_stat.wrong_count_login, 0);
    assert_eq!(user_stat.last_wrong_login_date, 0);
    assert_eq!(user_stat.attempt_change_pass, 0);
    assert_eq!(user_stat.last_attempt_change_pass_date, 0);
}

#[test]
fn test_duration_parsing() {
    let mut individual = Individual::default();
    
    // Test various duration formats
    individual.set_string("duration1", "1h", Lang::none());
    individual.set_string("duration2", "30m", Lang::none());
    individual.set_string("duration3", "1h 30m", Lang::none());
    individual.set_string("duration4", "1d", Lang::none());
    individual.set_string("invalid_duration", "invalid", Lang::none());
    
    // Call function from the project to parse durations
    let duration1 = veda_auth::read_duration_param(&mut individual, "duration1");
    let duration2 = veda_auth::read_duration_param(&mut individual, "duration2");
    let duration3 = veda_auth::read_duration_param(&mut individual, "duration3");
    let duration4 = veda_auth::read_duration_param(&mut individual, "duration4");
    let invalid_duration = veda_auth::read_duration_param(&mut individual, "invalid_duration");
    let missing_duration = veda_auth::read_duration_param(&mut individual, "missing");
    
    // Check results
    assert_eq!(duration1.unwrap().as_secs(), 3600); // 1 hour
    assert_eq!(duration2.unwrap().as_secs(), 1800); // 30 minutes
    assert_eq!(duration3.unwrap().as_secs(), 5400); // 1.5 hours
    assert_eq!(duration4.unwrap().as_secs(), 86400); // 1 day
    assert!(invalid_duration.is_none()); // Invalid format
    assert!(missing_duration.is_none()); // Missing parameter
}

#[test]
fn test_ticket_duration_calculations() {
    let storage_box = VStorage::builder()
        .memory()
        .build()
        .expect("Failed to create memory storage");
    let mut storage = VStorage::new(storage_box);
    
    let mut ticket = Ticket::default();
    let duration = 3600; // 1 hour
    
    // Create ticket
    veda_auth::create_new_ticket("user1", "test:user1", "127.0.0.1", duration, &mut ticket, &mut storage);
    
    // Check that ticket was created successfully
    assert_eq!(ticket.result, ResultCode::Ok);
    assert!(!ticket.id.is_empty());
    assert!(ticket.start_time > 0);
    assert!(ticket.end_time > ticket.start_time);
    
    // Check that end time matches specified duration
    let actual_duration = (ticket.end_time - ticket.start_time) / 10_000_000;
    assert_eq!(actual_duration, duration);
} 