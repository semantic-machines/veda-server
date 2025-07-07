use veda_auth::*;
use v_individual_model::onto::individual::Individual;
use v_storage::VStorage;
use v_common::module::ticket::Ticket;
use v_common::v_api::common_type::ResultCode;

/// Quick start example for veda-auth
/// 
/// This is the minimal code needed to get started with authentication
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Veda Auth Quick Start ===");
    
    // 1. Create storage
    let storage_box = VStorage::builder().memory().build()?;
    let mut storage = VStorage::new(storage_box);
    
    // 2. Create system ticket
    let sys_ticket = create_sys_ticket(&mut storage);
    println!("✓ System ticket: {}", sys_ticket.id);
    
    // 3. Create user credential
    let mut credential = Individual::default();
    credential.set_id("credential:user1");
    set_password(&mut credential, "secure_password_123");
    println!("✓ Password set for user");
    
    // 4. Create user ticket
    let mut ticket = Ticket::default();
    create_new_ticket("user1", "user:123", "127.0.0.1", 3600, &mut ticket, &mut storage);
    
    if ticket.result == ResultCode::Ok {
        println!("✓ User authenticated successfully!");
        println!("  Ticket ID: {}", ticket.id);
        println!("  Valid until: {}", ticket.end_time);
    } else {
        println!("✗ Authentication failed: {:?}", ticket.result);
    }
    
    // 5. Use default configuration
    let config = AuthConf::default();
    println!("✓ Configuration loaded:");
    println!("  - Max failed attempts: {}", config.failed_auth_attempts);
    println!("  - Ticket lifetime: {} hours", config.ticket_lifetime / 3600);
    
    println!("\nNext steps:");
    println!("1. Run 'cargo run --example basic_usage' for detailed examples");
    println!("2. Run 'cargo run --example simple_client' for client-server demo");
    println!("3. Check examples/README.md for more information");
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_quick_start() {
        // Test that the quick start example works
        let storage_box = VStorage::builder().memory().build().unwrap();
        let mut storage = VStorage::new(storage_box);
        
        let sys_ticket = create_sys_ticket(&mut storage);
        assert_eq!(sys_ticket.result, ResultCode::Ok);
        
        let mut credential = Individual::default();
        set_password(&mut credential, "test_password");
        assert!(credential.get_first_literal("v-s:password").is_some());
        
        let mut ticket = Ticket::default();
        create_new_ticket("test", "user:test", "127.0.0.1", 3600, &mut ticket, &mut storage);
        assert_eq!(ticket.result, ResultCode::Ok);
    }
} 