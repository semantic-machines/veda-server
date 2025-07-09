use tempfile::TempDir;

use veda_az_indexer::common::*;
use veda_az_indexer::acl_cache::*;

use v_individual_model::onto::individual::Individual;
use v_storage::{StorageMode, lmdb_storage::LmdbInstance};
use v_common::module::info::ModuleInfo;
use v_common::v_authorization::common::Access;

// Wrapper for LmdbInstance to implement Storage trait in tests
struct TestStorage(LmdbInstance);

impl TestStorage {
    fn new(path: &str, mode: StorageMode) -> Self {
        TestStorage(LmdbInstance::new(path, mode))
    }
}

impl Storage for TestStorage {
    fn get(&mut self, key: &str) -> Option<String> {
        self.0.get::<String>(key)
    }
    
    fn put(&mut self, key: &str, value: &str) -> bool {
        self.0.put(key, value)
    }
    
    fn remove(&mut self, key: &str) -> bool {
        self.0.remove(key)
    }
}

// Helper function to create a test context
fn create_test_context() -> Context {
    let temp_dir = TempDir::new().unwrap();
    let storage_path = temp_dir.path().join("test_storage");
    let module_info_path = temp_dir.path().join("test_module_info");
    
    Context {
        permission_statement_counter: 0,
        membership_counter: 0,
        storage: Box::new(TestStorage::new(storage_path.to_str().unwrap(), StorageMode::ReadWrite)),
        version_of_index_format: 2,
        module_info: ModuleInfo::new(module_info_path.to_str().unwrap(), "test_module", true).unwrap(),
        acl_cache: None,
    }
}

// Helper function to create a test individual
fn create_test_individual(id: &str, rdf_type: &str) -> Individual {
    let mut individual = Individual::default();
    individual.set_id(id);
    individual.add_uri("rdf:type", rdf_type);
    individual
}

#[test]
fn test_get_access_from_individual() {
    // Test case 1: Individual with all permissions
    let mut individual = create_test_individual("test:user1", "v-s:Account");
    individual.add_bool("v-s:canCreate", true);
    individual.add_bool("v-s:canRead", true);
    individual.add_bool("v-s:canUpdate", true);
    individual.add_bool("v-s:canDelete", true);
    
    let access = get_access_from_individual(&mut individual);
    assert_eq!(access, Access::CanCreate as u8 | Access::CanRead as u8 | Access::CanUpdate as u8 | Access::CanDelete as u8);
    
    // Test case 2: Individual with no permissions
    let mut individual2 = create_test_individual("test:user2", "v-s:Account");
    individual2.add_bool("v-s:canCreate", false);
    individual2.add_bool("v-s:canRead", false);
    individual2.add_bool("v-s:canUpdate", false);
    individual2.add_bool("v-s:canDelete", false);
    
    let access2 = get_access_from_individual(&mut individual2);
    assert_eq!(access2, Access::CantCreate as u8 | Access::CantRead as u8 | Access::CantUpdate as u8 | Access::CantDelete as u8);
    
    // Test case 3: Individual with mixed permissions
    let mut individual3 = create_test_individual("test:user3", "v-s:Account");
    individual3.add_bool("v-s:canCreate", true);
    individual3.add_bool("v-s:canRead", false);
    individual3.add_bool("v-s:canUpdate", true);
    individual3.add_bool("v-s:canDelete", false);
    
    let access3 = get_access_from_individual(&mut individual3);
    assert_eq!(access3, Access::CanCreate as u8 | Access::CantRead as u8 | Access::CanUpdate as u8 | Access::CantDelete as u8);
}

#[test]
fn test_get_disappeared() {
    // Test case 1: Elements that disappeared
    let a = vec!["item1".to_string(), "item2".to_string(), "item3".to_string()];
    let b = vec!["item1".to_string(), "item3".to_string()];
    let disappeared = get_disappeared(&a, &b);
    assert_eq!(disappeared, vec!["item2".to_string()]);
    
    // Test case 2: No elements disappeared
    let a2 = vec!["item1".to_string(), "item2".to_string()];
    let b2 = vec!["item1".to_string(), "item2".to_string()];
    let disappeared2 = get_disappeared(&a2, &b2);
    assert!(disappeared2.is_empty());
    
    // Test case 3: All elements disappeared
    let a3 = vec!["item1".to_string(), "item2".to_string()];
    let b3 = vec![];
    let disappeared3 = get_disappeared(&a3, &b3);
    assert_eq!(disappeared3, vec!["item1".to_string(), "item2".to_string()]);
    
    // Test case 4: Empty source array
    let a4 = vec![];
    let b4 = vec!["item1".to_string()];
    let disappeared4 = get_disappeared(&a4, &b4);
    assert!(disappeared4.is_empty());
}





#[test] 
fn test_acl_cache_new() {
    use ini::Ini;
    
    // Test case 1: Cache disabled
    let mut config = Ini::new();
    config.with_section(Some("authorization_cache"))
        .set("write", "false");
    
    let cache = ACLCache::new(&config);
    assert!(cache.is_none());
    
    // Test case 2: Cache enabled with default settings
    let mut config2 = Ini::new();
    config2.with_section(Some("authorization_cache"))
        .set("write", "true");
    
    let cache2 = ACLCache::new(&config2);
    assert!(cache2.is_some());
    
    // Test case 3: Cache enabled with custom settings
    let mut config3 = Ini::new();
    config3.with_section(Some("authorization_cache"))
        .set("write", "true")
        .set("expiration", "1d")
        .set("cleanup_time", "03:00:00")
        .set("cleanup_batch_time_limit", "200ms")
        .set("min_identifier_count_threshold", "50");
    
    let cache3 = ACLCache::new(&config3);
    assert!(cache3.is_some());
}

#[test]
fn test_clean_cache() {
    use ini::Ini;
    
    let mut config = Ini::new();
    config.with_section(Some("authorization_cache"))
        .set("write", "true")
        .set("expiration", "1s");
    
    let mut ctx = create_test_context();
    ctx.acl_cache = ACLCache::new(&config);
    
    // Test clean_cache function with cache enabled
    let result = clean_cache(&mut ctx);
    assert!(result.is_ok());
    
    // Test clean_cache function with cache disabled
    ctx.acl_cache = None;
    let result_no_cache = clean_cache(&mut ctx);
    assert!(result_no_cache.is_ok());
}

#[test]
fn test_process_stat_files() {
    use ini::Ini;
    
    let mut config = Ini::new();
    config.with_section(Some("authorization_cache"))
        .set("write", "true")
        .set("stat_processing_interval", "1s")
        .set("min_identifier_count_threshold", "1");
    
    let mut ctx = create_test_context();
    ctx.acl_cache = ACLCache::new(&config);
    
    // Test process_stat_files function - when no cache is configured, it should return Ok(false)
    ctx.acl_cache = None;
    let result = process_stat_files(&mut ctx);
    assert!(result.is_ok());
    assert!(!result.unwrap());
}

#[test]
fn test_storage_error_display() {
    let error = StorageError::StoragePutError {
        key: "test:key".to_string(),
        source: "test_storage".to_string(),
    };
    
    let error_string = format!("{error}");
    assert!(error_string.contains("test:key"));
    assert!(error_string.contains("test_storage"));
}

#[test]
fn test_context_creation() {
    let ctx = create_test_context();
    assert_eq!(ctx.permission_statement_counter, 0);
    assert_eq!(ctx.membership_counter, 0);
    assert_eq!(ctx.version_of_index_format, 2);
    assert!(ctx.acl_cache.is_none());
}

#[test]
fn test_individual_creation() {
    let mut individual = create_test_individual("test:id", "v-s:TestType");
    assert_eq!(individual.get_id(), "test:id");
    assert!(individual.any_exists("rdf:type", &["v-s:TestType"]));
}



 