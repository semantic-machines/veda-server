use nng::{Protocol, Socket, Message};
use nng::options::{Options, SendTimeout, RecvTimeout};
use serde_json::json;
use std::time::Duration;

/// Simple example client for veda-auth authentication server
/// 
/// This example shows how to connect to the authentication server
/// and perform basic authentication operations.
pub struct AuthClient {
    socket: Socket,
    auth_url: String,
}

impl AuthClient {
    /// Create a new authentication client
    pub fn new(auth_url: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let socket = Socket::new(Protocol::Req0)?;
        
        // Set timeouts
        socket.set_opt::<SendTimeout>(Some(Duration::from_secs(30)))?;
        socket.set_opt::<RecvTimeout>(Some(Duration::from_secs(30)))?;
        
        Ok(AuthClient {
            socket,
            auth_url: auth_url.to_string(),
        })
    }
    
    /// Connect to the authentication server
    pub fn connect(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.socket.dial(&self.auth_url)?;
        println!("Connected to authentication server at {}", self.auth_url);
        Ok(())
    }
    
    /// Authenticate with username and password
    pub fn authenticate(&self, login: &str, password: &str, ip: &str) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let request = json!({
            "function": "authenticate",
            "login": login,
            "password": password,
            "secret": "",
            "addr": ip
        });
        
        let msg = Message::from(request.to_string().as_bytes());
        self.socket.send(msg).map_err(|e| format!("Send error: {:?}", e))?;
        
        let response = self.socket.recv().map_err(|e| format!("Receive error: {:?}", e))?;
        let response_str = std::str::from_utf8(response.as_slice())?;
        let response_json: serde_json::Value = serde_json::from_str(response_str)?;
        
        Ok(response_json)
    }
    
    /// Authenticate with secret code for password reset
    pub fn authenticate_with_secret(&self, login: &str, password: &str, secret: &str, ip: &str) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let request = json!({
            "function": "authenticate",
            "login": login,
            "password": password,
            "secret": secret,
            "addr": ip
        });
        
        let msg = Message::from(request.to_string().as_bytes());
        self.socket.send(msg).map_err(|e| format!("Send error: {:?}", e))?;
        
        let response = self.socket.recv().map_err(|e| format!("Receive error: {:?}", e))?;
        let response_str = std::str::from_utf8(response.as_slice())?;
        let response_json: serde_json::Value = serde_json::from_str(response_str)?;
        
        Ok(response_json)
    }
    
    /// Request password reset by sending "?" as secret
    pub fn request_password_reset(&self, login: &str, ip: &str) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let request = json!({
            "function": "authenticate",
            "login": login,
            "password": "",
            "secret": "?",
            "addr": ip
        });
        
        let msg = Message::from(request.to_string().as_bytes());
        self.socket.send(msg).map_err(|e| format!("Send error: {:?}", e))?;
        
        let response = self.socket.recv().map_err(|e| format!("Receive error: {:?}", e))?;
        let response_str = std::str::from_utf8(response.as_slice())?;
        let response_json: serde_json::Value = serde_json::from_str(response_str)?;
        
        Ok(response_json)
    }
    
    /// Get trusted ticket for another user (requires permission)
    pub fn get_trusted_ticket(&self, ticket: &str, login: &str, ip: &str) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let request = json!({
            "function": "get_ticket_trusted",
            "ticket": ticket,
            "login": login,
            "addr": ip
        });
        
        let msg = Message::from(request.to_string().as_bytes());
        self.socket.send(msg).map_err(|e| format!("Send error: {:?}", e))?;
        
        let response = self.socket.recv().map_err(|e| format!("Receive error: {:?}", e))?;
        let response_str = std::str::from_utf8(response.as_slice())?;
        let response_json: serde_json::Value = serde_json::from_str(response_str)?;
        
        Ok(response_json)
    }
    
    /// Logout and invalidate ticket
    pub fn logout(&self, ticket: &str, ip: &str) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let request = json!({
            "function": "logout",
            "ticket": ticket,
            "addr": ip
        });
        
        let msg = Message::from(request.to_string().as_bytes());
        self.socket.send(msg).map_err(|e| format!("Send error: {:?}", e))?;
        
        let response = self.socket.recv().map_err(|e| format!("Receive error: {:?}", e))?;
        let response_str = std::str::from_utf8(response.as_slice())?;
        let response_json: serde_json::Value = serde_json::from_str(response_str)?;
        
        Ok(response_json)
    }
}

/// Example usage of the authentication client
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Veda Auth Client Example ===");
    println!("Note: This example requires a running auth server");
    
    // Example configuration - in real usage, server would need to be running
    let auth_url = "tcp://localhost:8080";
    println!("Attempting to connect to: {}", auth_url);
    
    // Note: We'll demonstrate the API without actually connecting 
    // since server may not be running
    let client_result = AuthClient::new(auth_url);
    match client_result {
        Ok(client) => {
            println!("✓ Client created successfully");
            
            // In real usage, you would call:
            // client.connect()?;
            // let auth_result = client.authenticate("admin", "password", "127.0.0.1")?;
            
            println!("Client methods available:");
            println!("  - authenticate(login, password, ip)");
            println!("  - authenticate_with_secret(login, password, secret, ip)");
            println!("  - request_password_reset(login, ip)");
            println!("  - get_trusted_ticket(ticket, login, ip)");
            println!("  - logout(ticket, ip)");
        },
        Err(e) => {
            println!("✗ Failed to create client: {}", e);
        }
    }
    
    // Example JSON request format
    println!("\n=== Example JSON Request Format ===");
    let example_request = json!({
        "function": "authenticate",
        "login": "admin",
        "password": "password_hash",
        "secret": "",
        "addr": "127.0.0.1"
    });
    println!("Authentication request: {}", serde_json::to_string_pretty(&example_request)?);
    
    // Example response format
    println!("\n=== Example JSON Response Format ===");
    let example_response = json!({
        "type": "ticket",
        "id": "ticket_id_123",
        "user_uri": "user:admin",
        "user_login": "admin",
        "result": 0,
        "end_time": 1640995200000i64,
        "auth_origin": "VEDA"
    });
    println!("Authentication response: {}", serde_json::to_string_pretty(&example_response)?);
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_auth_client_creation() {
        let client = AuthClient::new("tcp://localhost:8080");
        assert!(client.is_ok());
    }
    
    #[test]
    fn test_invalid_url() {
        let client = AuthClient::new("invalid://url");
        assert!(client.is_ok()); // URL validation happens during connect
    }
    
    #[test]
    fn test_json_request_format() {
        let request = json!({
            "function": "authenticate",
            "login": "test",
            "password": "test",
            "secret": "",
            "addr": "127.0.0.1"
        });
        
        assert_eq!(request["function"], "authenticate");
        assert_eq!(request["login"], "test");
        assert_eq!(request["password"], "test");
        assert_eq!(request["addr"], "127.0.0.1");
    }
} 