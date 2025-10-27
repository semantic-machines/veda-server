use tempfile::TempDir;
use veda_az_indexer::common::*;
use v_individual_model::onto::individual::Individual;
use v_storage::{StorageMode, lmdb_storage::LmdbInstance};
use v_common::module::info::ModuleInfo;

// Wrapper for LmdbInstance to implement Storage trait in tests
pub struct TestStorage(LmdbInstance);

impl TestStorage {
    pub fn new(path: &str, mode: StorageMode) -> Self {
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
pub fn create_test_context() -> Context {
    let temp_dir = TempDir::new().unwrap();
    let storage_path = temp_dir.path().join("test_storage");
    let deny_storage_path = temp_dir.path().join("test_deny_storage");
    let module_info_path = temp_dir.path().join("test_module_info");
    
    Context {
        permission_statement_counter: 0,
        membership_counter: 0,
        storage: Box::new(TestStorage::new(storage_path.to_str().unwrap(), StorageMode::ReadWrite)),
        deny_storage: Box::new(TestStorage::new(deny_storage_path.to_str().unwrap(), StorageMode::ReadWrite)),
        version_of_index_format: 2,
        module_info: ModuleInfo::new(module_info_path.to_str().unwrap(), "test_module", true).unwrap(),
        acl_cache: None,
    }
}

// Helper function to create a test individual
pub fn create_test_individual(id: &str, rdf_type: &str) -> Individual {
    let mut individual = Individual::default();
    individual.set_id(id);
    individual.add_uri("rdf:type", rdf_type);
    individual
}

// Helper function to copy individual data (very simple version for tests)
// NOTE: This only copies common predicates used in tests
pub fn copy_individual_data(source: &mut Individual) -> Individual {
    let mut target = Individual::default();
    target.set_id(source.get_id());
    
    // Copy common URI predicates
    let predicates = ["rdf:type", "v-s:permissionObject", "v-s:permissionSubject", 
                      "v-s:resource", "v-s:memberOf"];
    
    for pred in &predicates {
        if let Some(uris) = source.get_literals(pred) {
            for uri in uris {
                target.add_uri(pred, &uri);
            }
        }
    }
    
    // Copy common boolean predicates
    let bool_predicates = ["v-s:canCreate", "v-s:canRead", "v-s:canUpdate", "v-s:canDelete", 
                           "v-s:deleted", "v-s:dropCount", "v-s:isExclusive", "v-s:ignoreExclusive"];
    
    for pred in &bool_predicates {
        if let Some(val) = source.get_first_bool(pred) {
            target.add_bool(pred, val);
        }
    }
    
    // Copy update counter
    if let Some(val) = source.get_first_integer("v-s:updateCounter") {
        target.add_integer("v-s:updateCounter", val);
    }
    
    target
}



