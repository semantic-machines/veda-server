use crate::app::App;
use crate::common::{start_module, stop_process, is_ok_process, log_info_and_to_tg, log_err_and_to_tg};
use chrono::prelude::*;
use clap::{Parser, Subcommand};
use env_logger::Builder;
use log::LevelFilter;
use std::collections::HashMap;
use std::io::Write;
use std::time::Duration;
use std::{thread, io, process};
use sysinfo::{System, SystemExt, ProcessExt};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(name = "veda-bootstrap")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Restart modules matching a pattern
    Restart {
        /// Pattern to match module names (e.g., "web-api" matches "web-api-0", "web-api-1", etc.)
        pattern: String,
        /// Timeout between restarts in seconds (default: 5)
        #[arg(long, default_value_t = 5)]
        timeout: u64,
    },
    /// List all configured modules
    List,
    /// Show status of all modules
    Status,
    /// Stop modules matching a pattern
    Stop {
        /// Pattern to match module names
        pattern: String,
    },
    /// Start modules matching a pattern
    Start {
        /// Pattern to match module names  
        pattern: String,
    },
}

/// Main CLI handler function - checks for CLI arguments and handles CLI mode
pub async fn handle_cli_mode() -> bool {
    // Check if we have CLI arguments
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 {
        // If --id is present, this is not CLI mode (daemon mode with --id parameter)
        if args.iter().any(|arg| arg == "--id" || arg.starts_with("--id=")) {
            return false; // Not CLI mode, continue with daemon mode
        }
        // CLI mode - parse arguments and execute command
        match Cli::try_parse() {
            Ok(cli) => {
                // Setup basic logging for CLI mode
                Builder::new()
                    .format(|buf, record| writeln!(buf, "{} [{}] - {}", Local::now().format("%Y-%m-%dT%H:%M:%S%.3f"), record.level(), record.args()))
                    .filter(None, LevelFilter::Warn) // Less verbose for CLI
                    .init();

                match CliApp::new().await {
                    Ok(mut cli_app) => {
                        if let Err(e) = cli_app.run_command(cli.command).await {
                            eprintln!("❌ CLI command failed: {:?}", e);
                            process::exit(1);
                        }
                    }
                    Err(e) => {
                        eprintln!("❌ Failed to initialize CLI: {:?}", e);
                        process::exit(1);
                    }
                }
                return true; // CLI mode was handled
            }
            Err(e) => {
                // Print help or error message
                eprintln!("{}", e);
                process::exit(1);
            }
        }
    }
    
    false // Not CLI mode, continue with daemon mode
}

pub struct CliApp {
    pub app: App,
    pub running_modules: HashMap<String, u32>, // module_name -> pid
}

impl CliApp {
    pub async fn new() -> io::Result<Self> {
        let mut app = App::new();
        let app_dir = if let Ok(s) = std::env::var("APPDIR") {
            s.as_str().to_string() + "/"
        } else {
            "./".to_string()
        };
        app.app_dir = app_dir;
        
        if let Some(n) = app.get_property("name") {
            app.name = n.to_string();
        }
        
        app.get_tg_dest();
        app.get_modules_info()?;
        
        let mut cli_app = CliApp {
            app,
            running_modules: HashMap::new(),
        };
        
        cli_app.discover_running_modules();
        
        Ok(cli_app)
    }
    
    /// Discover currently running modules by reading PID files
    fn discover_running_modules(&mut self) {
        use std::fs;
        use std::path::Path;
        
        let pids_dir = Path::new(".pids");
        if !pids_dir.exists() {
            return;
        }
        
        let mut sys = System::new();
        sys.refresh_processes();
        
        if let Ok(entries) = fs::read_dir(pids_dir) {
            for entry in entries.flatten() {
                if let Some(filename) = entry.file_name().to_str() {
                    if filename.ends_with("-pid") && filename.starts_with("__") {
                        let module_name = &filename[2..filename.len() - 4]; // Remove "__" prefix and "-pid" suffix
                        
                        if let Ok(pid_str) = fs::read_to_string(entry.path()) {
                            if let Ok(pid) = pid_str.trim().parse::<u32>() {
                                // Check if process is actually running
                                if sys.get_process(pid as i32).is_some() {
                                    self.running_modules.insert(module_name.to_string(), pid);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    pub async fn run_command(&mut self, cmd: Commands) -> io::Result<()> {
        match cmd {
            Commands::Restart { pattern, timeout } => {
                self.restart_modules_by_pattern(&pattern, timeout).await
            }
            Commands::List => {
                self.list_modules()
            }
            Commands::Status => {
                self.show_status().await
            }
            Commands::Stop { pattern } => {
                self.stop_modules_by_pattern(&pattern).await
            }
            Commands::Start { pattern } => {
                self.start_modules_by_pattern(&pattern).await
            }
        }
    }
    
    /// Find modules by pattern with smart matching:
    /// 1. First tries exact match - if module with exact name exists, returns only that module
    /// 2. If no exact match found, returns all modules starting with the pattern
    /// 
    /// Examples:
    /// - "web-api-2" -> returns only ["web-api-2"] if it exists
    /// - "web-api" -> returns ["web-api-0", "web-api-1", "web-api-2"] if no exact "web-api" exists
    fn find_modules_by_pattern(&self, pattern: &str) -> Vec<String> {
        // First check for exact match
        if self.app.modules_info.contains_key(pattern) {
            return vec![pattern.to_string()];
        }
        
        // If no exact match, find all modules starting with the pattern
        self.app.modules_info
            .keys()
            .filter(|name| name.starts_with(pattern))
            .cloned()
            .collect()
    }
    
    async fn restart_modules_by_pattern(&mut self, pattern: &str, timeout_secs: u64) -> io::Result<()> {
        let matching_modules = self.find_modules_by_pattern(pattern);
        
        if matching_modules.is_empty() {
            println!("No modules found matching pattern: {}", pattern);
            return Ok(());
        }
        
        println!("Found {} modules matching pattern '{}': {:?}", 
                matching_modules.len(), pattern, matching_modules);
        
        let timeout = Duration::from_secs(timeout_secs);
        let tg_dest = self.app.get_tg_dest();
        
        for module_name in matching_modules {
            println!("\n🔄 Restarting module: {}", module_name);
            
            // Check if module is currently running
            if let Some(&pid) = self.running_modules.get(&module_name) {
                println!("  ⏹️  Stopping process {} ({})", pid, module_name);
                
                // Send SIGTERM to stop the process
                if stop_process(pid as i32, &module_name) {
                    // Wait for process to stop
                    let mut sys = System::new();
                    let mut stopped = false;
                    
                    for attempt in 0..30 { // Wait up to 30 seconds
                        thread::sleep(Duration::from_millis(1000));
                        sys.refresh_processes();
                        
                        if sys.get_process(pid as i32).is_none() {
                            stopped = true;
                            break;
                        }
                        
                        if attempt % 5 == 4 {
                            println!("  ⏳ Waiting for process to stop... ({}/30s)", attempt + 1);
                        }
                    }
                    
                    if !stopped {
                        log_err_and_to_tg(&tg_dest, 
                            &format!("❌ Module {} did not stop within 30 seconds", module_name)).await;
                        continue;
                    }
                    
                    println!("  ✅ Process stopped successfully");
                } else {
                    println!("  ⚠️  Failed to send stop signal to process");
                }
                
                // Remove from running modules
                self.running_modules.remove(&module_name);
            } else {
                println!("  ℹ️  Module is not currently running");
            }
            
            // Start the module
            if let Some(module) = self.app.modules_info.get_mut(&module_name) {
                println!("  ⏵️  Starting module: {}", module_name);
                
                match start_module(module).await {
                    Ok(child) => {
                        let pid = child.id();
                        println!("  ✅ Module started with PID: {}", pid);
                        
                        // Wait a bit and verify the process is still running
                        thread::sleep(Duration::from_millis(1000));
                        
                        let mut sys = System::new();
                        sys.refresh_processes();
                        
                        if is_ok_process(&mut sys, pid).0 {
                            self.running_modules.insert(module_name.clone(), pid);
                            log_info_and_to_tg(&tg_dest, 
                                &format!("✅ Module {} successfully restarted (PID: {})", module_name, pid)).await;
                        } else {
                            log_err_and_to_tg(&tg_dest, 
                                &format!("❌ Module {} started but failed immediately", module_name)).await;
                        }
                    }
                    Err(e) => {
                        let error_msg = format!("❌ Failed to start module {}: {:?}", module_name, e);
                        println!("  {}", error_msg);
                        log_err_and_to_tg(&tg_dest, &error_msg).await;
                    }
                }
            } else {
                println!("  ❌ Module configuration not found: {}", module_name);
            }
            
            // Wait timeout before processing next module (except for the last one)
            if timeout_secs > 0 {
                println!("  ⏳ Waiting {} seconds before next restart...", timeout_secs);
                thread::sleep(timeout);
            }
        }
        
        Ok(())
    }
    
    async fn stop_modules_by_pattern(&mut self, pattern: &str) -> io::Result<()> {
        let matching_modules = self.find_modules_by_pattern(pattern);
        
        if matching_modules.is_empty() {
            println!("No modules found matching pattern: {}", pattern);
            return Ok(());
        }
        
        println!("Stopping {} modules matching pattern '{}': {:?}", 
                matching_modules.len(), pattern, matching_modules);
        
        for module_name in matching_modules {
            if let Some(&pid) = self.running_modules.get(&module_name) {
                println!("⏹️ Stopping module {} (PID: {})", module_name, pid);
                
                if stop_process(pid as i32, &module_name) {
                    self.running_modules.remove(&module_name);
                    println!("✅ Sent stop signal to {}", module_name);
                } else {
                    println!("❌ Failed to stop {}", module_name);
                }
            } else {
                println!("ℹ️ Module {} is not running", module_name);
            }
        }
        
        Ok(())
    }
    
    async fn start_modules_by_pattern(&mut self, pattern: &str) -> io::Result<()> {
        let matching_modules = self.find_modules_by_pattern(pattern);
        
        if matching_modules.is_empty() {
            println!("No modules found matching pattern: {}", pattern);
            return Ok(());
        }
        
        println!("Starting {} modules matching pattern '{}': {:?}", 
                matching_modules.len(), pattern, matching_modules);
        
        for module_name in matching_modules {
            if self.running_modules.contains_key(&module_name) {
                println!("ℹ️ Module {} is already running", module_name);
                continue;
            }
            
            if let Some(module) = self.app.modules_info.get_mut(&module_name) {
                println!("⏵️ Starting module: {}", module_name);
                
                match start_module(module).await {
                    Ok(child) => {
                        let pid = child.id();
                        self.running_modules.insert(module_name.clone(), pid);
                        println!("✅ Module {} started with PID: {}", module_name, pid);
                    }
                    Err(e) => {
                        println!("❌ Failed to start module {}: {:?}", module_name, e);
                    }
                }
            } else {
                println!("❌ Module configuration not found: {}", module_name);
            }
        }
        
        Ok(())
    }
    
    fn list_modules(&self) -> io::Result<()> {
        println!("📋 Configured modules:");
        
        let mut modules: Vec<_> = self.app.modules_info.iter().collect();
        modules.sort_by(|a, b| a.1.order.cmp(&b.1.order));
        
        for (name, module) in modules {
            let status = if self.running_modules.contains_key(name) {
                "🟢 RUNNING"
            } else {
                "🔴 STOPPED"
            };
            
            println!("  {} {} ({})", status, name, module.module_name);
            if !module.args.is_empty() {
                println!("      args: {:?}", module.args);
            }
            if let Some(memory_limit) = module.memory_limit {
                println!("      memory-limit: {} KiB", memory_limit);
            }
        }
        
        Ok(())
    }
    
    async fn show_status(&mut self) -> io::Result<()> {
        println!("📊 Module status:");
        
        // Refresh system info
        let mut sys = System::new();
        sys.refresh_processes();
        
        // Update running modules info
        let mut to_remove = Vec::new();
        for (module_name, &pid) in &self.running_modules {
            if sys.get_process(pid as i32).is_none() {
                to_remove.push(module_name.clone());
            }
        }
        
        for module_name in to_remove {
            self.running_modules.remove(&module_name);
        }
        
        let mut modules: Vec<_> = self.app.modules_info.iter().collect();
        modules.sort_by(|a, b| a.1.order.cmp(&b.1.order));
        
        for (name, _module) in modules {
            if let Some(&pid) = self.running_modules.get(name) {
                if let Some(process) = sys.get_process(pid as i32) {
                    let memory_mb = process.memory() / 1024;
                    println!("🟢 {} (PID: {}, Memory: {} MiB)", name, pid, memory_mb);
                } else {
                    println!("🟡 {} (PID: {} - process not found)", name, pid);
                }
            } else {
                println!("🔴 {} (stopped)", name);
            }
        }
        
        Ok(())
    }
}
