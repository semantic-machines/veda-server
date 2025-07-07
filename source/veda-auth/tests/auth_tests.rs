use veda_auth::*;
use v_individual_model::onto::individual::Individual;
use v_individual_model::onto::datatype::Lang;
use v_common::module::ticket::Ticket;
use v_storage::{VStorage};
use v_common::v_api::common_type::ResultCode;
use chrono::Utc;

#[test]
fn test_auth_workplace_struct_fields() {
    // Тестируем что структуры AuthConf и UserStat можно создать
    let conf = AuthConf::default();
    let mut user_stat = UserStat::default();
    let mut credential = Individual::default();
    
    // Тестовые данные
    let login = "test_user";
    let password = "test_password";
    let ip = "127.0.0.1";
    let secret = "";
    let sys_ticket = "test_ticket";
    
    // Проверяем что можем создать и использовать поля
    assert_eq!(conf.failed_auth_attempts, 2);
    assert_eq!(user_stat.wrong_count_login, 0);
    assert_eq!(login, "test_user");
    assert_eq!(password, "test_password");
    assert_eq!(ip, "127.0.0.1");
    assert_eq!(secret, "");
    assert_eq!(sys_ticket, "test_ticket");
    
    // Проверяем что можем изменять поля
    user_stat.wrong_count_login = 5;
    assert_eq!(user_stat.wrong_count_login, 5);
    
    credential.set_id("test_credential");
    assert_eq!(credential.get_id(), "test_credential");
}

#[test]
fn test_password_hashing_consistency() {
    // Тестируем что одинаковые пароли с разными солями дают разные хеши
    let mut credential1 = Individual::default();
    let mut credential2 = Individual::default();
    
    let password = "TestPassword123!";
    
    // Вызываем функцию из проекта дважды для одного и того же пароля
    veda_auth::set_password(&mut credential1, password);
    veda_auth::set_password(&mut credential2, password);
    
    let hash1 = credential1.get_first_literal("v-s:password").unwrap();
    let hash2 = credential2.get_first_literal("v-s:password").unwrap();
    let salt1 = credential1.get_first_literal("v-s:salt").unwrap();
    let salt2 = credential2.get_first_literal("v-s:salt").unwrap();
    
    // Даже для одного и того же пароля должны быть разные соли и хеши
    assert_ne!(hash1, hash2);
    assert_ne!(salt1, salt2);
    
    // Но формат должен быть одинаковый
    assert_eq!(hash1.len(), hash2.len());
    assert_eq!(salt1.len(), salt2.len());
}

#[test]
fn test_empty_password_handling() {
    let mut credential = Individual::default();
    
    // Тестируем с пустым паролем
    veda_auth::set_password(&mut credential, "");
    
    let stored_password = credential.get_first_literal("v-s:password");
    
    // Даже для пустого пароля должен быть создан хеш
    assert!(stored_password.is_some());
    let stored_password = stored_password.unwrap();
    assert!(!stored_password.is_empty());
}

#[test]
fn test_special_characters_in_password() {
    let mut credential = Individual::default();
    
    // Тестируем с паролем, содержащим специальные символы
    let password = "!@#$%^&*()_+-=[]{}|;':\",./<>?`~";
    veda_auth::set_password(&mut credential, password);
    
    let stored_password = credential.get_first_literal("v-s:password");
    let stored_salt = credential.get_first_literal("v-s:salt");
    
    assert!(stored_password.is_some());
    assert!(stored_salt.is_some());
    
    let stored_password = stored_password.unwrap();
    let stored_salt = stored_salt.unwrap();
    
    // Проверяем что хеш и соль созданы правильно
    assert_eq!(stored_password.len(), 128);
    assert_eq!(stored_salt.len(), 128);
    assert!(stored_password.chars().all(|c| c.is_ascii_hexdigit()));
    assert!(stored_salt.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_unicode_password_handling() {
    let mut credential = Individual::default();
    
    // Тестируем с паролем, содержащим Unicode символы
    let password = "Пароль123фёё🔒🛡️";
    veda_auth::set_password(&mut credential, password);
    
    let stored_password = credential.get_first_literal("v-s:password");
    let stored_salt = credential.get_first_literal("v-s:salt");
    
    assert!(stored_password.is_some());
    assert!(stored_salt.is_some());
    
    let stored_password = stored_password.unwrap();
    let stored_salt = stored_salt.unwrap();
    
    // Проверяем что хеш и соль созданы правильно даже для Unicode
    assert_eq!(stored_password.len(), 128);
    assert_eq!(stored_salt.len(), 128);
    assert!(stored_password.chars().all(|c| c.is_ascii_hexdigit()));
    assert!(stored_salt.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_very_long_password() {
    let mut credential = Individual::default();
    
    // Тестируем с очень длинным паролем
    let password = "A".repeat(1000); // 1000 символов
    veda_auth::set_password(&mut credential, &password);
    
    let stored_password = credential.get_first_literal("v-s:password");
    let stored_salt = credential.get_first_literal("v-s:salt");
    
    assert!(stored_password.is_some());
    assert!(stored_salt.is_some());
    
    let stored_password = stored_password.unwrap();
    let stored_salt = stored_salt.unwrap();
    
    // Длина хеша должна быть фиксированной независимо от длины пароля
    assert_eq!(stored_password.len(), 128);
    assert_eq!(stored_salt.len(), 128);
}

#[test]
fn test_ticket_creation_with_different_durations() {
    let storage_box = VStorage::builder()
        .memory()
        .build()
        .expect("Failed to create memory storage");
    let mut storage = VStorage::new(storage_box);
    
    let login = "test_user";
    let user_id = "test:user123";
    let addr = "127.0.0.1";
    
    // Тестируем разные длительности
    let durations = vec![60, 3600, 86400, 604800]; // 1 мин, 1 час, 1 день, 1 неделя
    
    for duration in durations {
        let mut ticket = Ticket::default();
        
        // Вызываем функцию из проекта
        veda_auth::create_new_ticket(login, user_id, addr, duration, &mut ticket, &mut storage);
        
        // Проверяем что длительность установлена правильно
        let actual_duration = (ticket.end_time - ticket.start_time) / 10_000_000;
        assert_eq!(actual_duration, duration);
        assert_eq!(ticket.result, ResultCode::Ok);
    }
}

#[test]
fn test_ticket_creation_with_different_ip_addresses() {
    let storage_box = VStorage::builder()
        .memory()
        .build()
        .expect("Failed to create memory storage");
    let mut storage = VStorage::new(storage_box);
    
    let login = "test_user";
    let user_id = "test:user123";
    let duration = 3600;
    
    // Тестируем разные валидные IP адреса
    let valid_ips = vec![
        "127.0.0.1",
        "192.168.1.1",
        "10.0.0.1",
        "172.16.0.1",
        "8.8.8.8",
        "::1",
        "2001:db8::1",
    ];
    
    for ip in valid_ips {
        let mut ticket = Ticket::default();
        
        // Вызываем функцию из проекта
        veda_auth::create_new_ticket(login, user_id, ip, duration, &mut ticket, &mut storage);
        
        // Проверяем что билет создан успешно
        assert_eq!(ticket.result, ResultCode::Ok);
        assert_eq!(ticket.user_addr, ip);
        assert!(!ticket.id.is_empty());
    }
}

#[test]
fn test_ticket_creation_with_invalid_ip_addresses() {
    let storage_box = VStorage::builder()
        .memory()
        .build()
        .expect("Failed to create memory storage");
    let mut storage = VStorage::new(storage_box);
    
    let login = "test_user";
    let user_id = "test:user123";
    let duration = 3600;
    
    // Тестируем невалидные IP адреса
    let invalid_ips = vec![
        "999.999.999.999",
        "not_an_ip",
        "192.168.1",
        "192.168.1.1.1",
        "",
        "localhost",
        "300.300.300.300",
    ];
    
    for ip in invalid_ips {
        let mut ticket = Ticket::default();
        
        // Вызываем функцию из проекта
        veda_auth::create_new_ticket(login, user_id, ip, duration, &mut ticket, &mut storage);
        
        // Билет не должен быть создан для невалидного IP
        assert!(ticket.id.is_empty());
    }
}

#[test]
fn test_constants_values() {
    // Проверяем что константы имеют ожидаемые значения
    assert_eq!(veda_auth::N_ITER, 100_000);
    assert_eq!(veda_auth::TICKS_TO_UNIX_EPOCH, 62_135_596_800_000);
    
    // Проверяем что пустой SHA256 хеш имеет правильный формат
    let empty_hash = veda_auth::EMPTY_SHA256_HASH;
    assert_eq!(empty_hash.len(), 64);
    assert!(empty_hash.chars().all(|c| c.is_ascii_hexdigit()));
    
    // Проверяем что группа доверенных пользователей имеет правильный формат
    let trusted_group = veda_auth::ALLOW_TRUSTED_GROUP;
    assert!(trusted_group.starts_with("cfg:"));
    assert!(trusted_group.contains("Trusted"));
}

#[test]
fn test_auth_configuration_ranges() {
    let conf = AuthConf::default();
    
    // Проверяем что все значения находятся в разумных пределах
    assert!(conf.failed_auth_attempts > 0);
    assert!(conf.failed_auth_attempts < 100);
    
    assert!(conf.failed_change_pass_attempts > 0);
    assert!(conf.failed_change_pass_attempts < 100);
    
    assert!(conf.failed_auth_lock_period > 0);
    assert!(conf.failed_auth_lock_period < 86400 * 7); // Меньше недели
    
    assert!(conf.ticket_lifetime > 0);
    assert!(conf.ticket_lifetime < 86400 * 30); // Меньше месяца
    
    assert!(conf.pass_lifetime > 0);
    assert!(conf.pass_lifetime < 86400 * 365); // Меньше года
}

#[test]
fn test_user_stat_field_types() {
    let mut user_stat = UserStat::default();
    
    // Проверяем что можно изменять поля
    user_stat.wrong_count_login = 5;
    user_stat.last_wrong_login_date = Utc::now().timestamp();
    user_stat.attempt_change_pass = 3;
    user_stat.last_attempt_change_pass_date = Utc::now().timestamp();
    
    assert_eq!(user_stat.wrong_count_login, 5);
    assert!(user_stat.last_wrong_login_date > 0);
    assert_eq!(user_stat.attempt_change_pass, 3);
    assert!(user_stat.last_attempt_change_pass_date > 0);
}

#[test]
fn test_duration_param_edge_cases() {
    let mut individual = Individual::default();
    
    // Тестируем граничные случаи
    individual.set_string("zero_duration", "0s", Lang::none());
    individual.set_string("negative_duration", "-1h", Lang::none());
    individual.set_string("fractional_duration", "0.5h", Lang::none());
    individual.set_string("very_large_duration", "1000d", Lang::none());
    
    // Вызываем функцию из проекта
    let zero_duration = veda_auth::read_duration_param(&mut individual, "zero_duration");
    let negative_duration = veda_auth::read_duration_param(&mut individual, "negative_duration");
    let fractional_duration = veda_auth::read_duration_param(&mut individual, "fractional_duration");
    let very_large_duration = veda_auth::read_duration_param(&mut individual, "very_large_duration");
    
    // Проверяем результаты
    assert_eq!(zero_duration.unwrap().as_secs(), 0);
    assert!(negative_duration.is_none()); // Отрицательные значения должны быть недопустимы
    assert_eq!(fractional_duration.unwrap().as_secs(), 1800); // 0.5 часа = 30 минут
    assert_eq!(very_large_duration.unwrap().as_secs(), 86400 * 1000); // 1000 дней
} 