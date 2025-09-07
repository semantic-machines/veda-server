use log::{error, info};
use v_individual_model::onto::individual::Individual;
use v_individual_model::onto::datatype::Lang;
use v_common::v_api::common_type::ResultCode;
use v_common::module::veda_backend::Backend;
use v_common::v_api::api_client::IndvOp;

// Mobile authentication helper functions
pub struct MobileAuth;

impl MobileAuth {
    // Check if login is a valid phone number (with or without + prefix)
    fn is_valid_phone_number(login: &str) -> bool {
        // Count digits in the login
        let digit_count = login.chars().filter(|c| c.is_numeric()).count();

        // Check if format is valid
        let valid_format = if login.starts_with('+') {
            // After + should be only digits
            login.chars().skip(1).all(|c| c.is_numeric()) && digit_count >= 10
        } else {
            // Should be only digits
            login.chars().all(|c| c.is_numeric()) && digit_count >= 10
        };

        valid_format
    }

    // Check if this is a request to send SMS code (first step: phone + empty password + empty secret)
    pub fn is_sms_code_request(login: &str, password: &str, secret: &str) -> bool {
        // Check if login is phone number
        let login_is_phone = Self::is_valid_phone_number(login);

        // Check if password is empty
        let password_empty = password.is_empty() || password == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        // Check if secret is empty (this is the key difference from verification step)
        let secret_empty = secret.is_empty();

        login_is_phone && password_empty && secret_empty
    }

    // Check if this is SMS code verification request
    pub fn is_sms_code_verification(login: &str, password: &str, secret: &str, account: &mut Individual) -> bool {
        // Check if account has mobile auth origin
        let auth_origin = account.get_first_literal("v-s:authOrigin").unwrap_or_default();
        if auth_origin.to_uppercase() != "MOBILE" {
            return false;
        }

        // Check if login is a valid phone number
        let login_is_valid_phone = Self::is_valid_phone_number(login);
        if !login_is_valid_phone {
            return false;
        }

        // Check if password is empty and secret is filled
        let password_empty = password.is_empty() || password == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let secret_filled = !secret.is_empty() && secret.len() >= 4 && secret.chars().all(|c| c.is_numeric());

        password_empty && secret_filled
    }

    // Normalize phone number for SMS sending
    pub fn normalize_phone_number(phone: &str) -> String {
        // Remove '+' and any non-digit characters
        let digits: String = phone.chars().filter(|c| c.is_ascii_digit()).collect();
        
        // Handle Russian phone number formats
        match digits.len() {
            11 if digits.starts_with('7') => digits,
            11 if digits.starts_with('8') => format!("7{}", &digits[1..]),
            10 => format!("7{}", digits),
            _ => digits, // Return as-is for other formats
        }
    }

    // Create SMS request individual for queue processing
    pub fn send_sms_code_with_backend(phone: &str, code: &str, backend: &mut Backend, sys_ticket: &str) -> ResultCode {
        // Normalize phone number
        let normalized_phone = Self::normalize_phone_number(phone);
        
        // Create SMS message
        let message = format!("Ваш код для входа: {}. Никому его не сообщайте.", code);
        
        info!("Creating SMS request individual for phone: {}", normalized_phone);
        
        // Generate unique ID for SMS
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis();
        let sms_id = format!("d:sms_{}", timestamp);
        
        let mut sms_individual = Individual::default();
        sms_individual.set_id(&sms_id);
        
        // Set required properties for SMS (following v-s:Email pattern)
        sms_individual.add_uri("rdf:type", "v-s:Sms");
        sms_individual.add_string("v-s:recipientPhone", &normalized_phone, Lang::none());
        sms_individual.add_string("v-s:messageBody", &message, Lang::none());
        sms_individual.add_datetime("v-s:created", chrono::Utc::now().timestamp());
        // Add v-s:Deliverable properties
        sms_individual.add_bool("v-s:isSuccess", false);
        sms_individual.add_string("v-s:infoOfExecuting", "", Lang::none());
        
        // Put individual to storage/queue
        let res = backend.mstorage_api.update_use_param(sys_ticket, "request_sms_code",
                                                        "az", 0,
                                                        IndvOp::Put, &sms_individual);
        match res {
            Ok(op_result) => op_result,
            Err(e) => {
                error!("Failed to store SMS individual, id = {}, error = {:?}", sms_id, e);
                return ResultCode::InternalServerError;
            }
        };
        
        info!("SMS individual created and stored: {}", sms_id);
        info!("Phone: {}, Message: {}", normalized_phone, message);
        
        ResultCode::Ok
    }
}