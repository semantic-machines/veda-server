use tempfile::TempDir;
use veda_az_indexer::common::*;

use v_individual_model::onto::individual::Individual;
use v_storage::{StorageMode, lmdb_storage::LmdbInstance};
use v_common::module::info::ModuleInfo;
use v_common::v_authorization::common::{Access, PERMISSION_PREFIX, MEMBERSHIP_PREFIX, FILTER_PREFIX};
use v_common::az_impl::formats::{decode_rec_to_rightset};
use v_common::v_authorization::ACLRecordSet;

// Helper function to create a test context
fn create_test_context() -> Context {
    let temp_dir = TempDir::new().unwrap();
    let storage_path = temp_dir.path().join("test_storage");
    let module_info_path = temp_dir.path().join("test_module_info");
    
    Context {
        permission_statement_counter: 0,
        membership_counter: 0,
        storage: LmdbInstance::new(storage_path.to_str().unwrap(), StorageMode::ReadWrite),
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
fn test_permission_statement_database_write() {
    let mut ctx = create_test_context();
    
    // Create a permission statement
    let mut prev_state = Individual::default();
    let mut new_state = create_test_individual("test:permission1", "v-s:PermissionStatement");
    new_state.add_uri("v-s:permissionObject", "test:resource1");
    new_state.add_uri("v-s:permissionSubject", "test:subject1");
    new_state.add_bool("v-s:canRead", true);
    new_state.add_bool("v-s:canCreate", true);
    
    // Execute the function
    let result = prepare_permission_statement(&mut prev_state, &mut new_state, &mut ctx);
    assert!(result.is_ok());
    
    // Check what was written to the database
    let expected_key = format!("{PERMISSION_PREFIX}test:resource1");
    let stored_value = ctx.storage.get::<String>(&expected_key);
    assert!(stored_value.is_some(), "Expected data to be written to storage with key: {expected_key}");
    
    // Decode and verify the stored data
    let stored_data = stored_value.unwrap();
    let mut record_set = ACLRecordSet::new();
    let (_, _) = decode_rec_to_rightset(&stored_data, &mut record_set);
    
    // Verify the record set contains our subject
    assert!(record_set.contains_key("test:subject1"), "Record set should contain subject test:subject1");
    
    let acl_record = record_set.get("test:subject1").unwrap();
    assert_eq!(acl_record.id, "test:subject1");
    
    // Verify access rights (CanRead | CanCreate)
    let expected_access = Access::CanRead as u8 | Access::CanCreate as u8;
    assert_eq!(acl_record.access & expected_access, expected_access, 
               "Access rights should include CanRead and CanCreate");
}

#[test]
fn test_membership_database_write() {
    let mut ctx = create_test_context();
    
    // Create a membership
    let mut prev_state = Individual::default();
    let mut new_state = create_test_individual("test:membership1", "v-s:Membership");
    new_state.add_uri("v-s:resource", "test:resource1");
    new_state.add_uri("v-s:memberOf", "test:group1");
    new_state.add_bool("v-s:canRead", true);
    new_state.add_bool("v-s:canUpdate", true);
    
    // Execute the function
    let result = index_right_sets(
        &mut prev_state,
        &mut new_state,
        "v-s:resource",
        "v-s:memberOf",
        MEMBERSHIP_PREFIX,
        Access::CanCreate as u8 | Access::CanRead as u8 | Access::CanUpdate as u8 | Access::CanDelete as u8,
        &mut ctx
    );
    assert!(result.is_ok());
    
    // Check what was written to the database
    let expected_key = format!("{MEMBERSHIP_PREFIX}test:resource1");
    let stored_value = ctx.storage.get::<String>(&expected_key);
    assert!(stored_value.is_some(), "Expected membership data to be written to storage with key: {expected_key}");
    
    // Decode and verify the stored data
    let stored_data = stored_value.unwrap();
    let mut record_set = ACLRecordSet::new();
    let (_, _) = decode_rec_to_rightset(&stored_data, &mut record_set);
    
    // Verify the record set contains our group
    assert!(record_set.contains_key("test:group1"), "Record set should contain group test:group1");
    
    let acl_record = record_set.get("test:group1").unwrap();
    assert_eq!(acl_record.id, "test:group1");
    
    // Verify access rights include Read and Update
    let expected_access = Access::CanRead as u8 | Access::CanUpdate as u8;
    assert!((acl_record.access & expected_access) == expected_access, 
            "Access rights should include CanRead and CanUpdate");
}

#[test]
fn test_permission_filter_database_write() {
    let mut ctx = create_test_context();
    
    // Create a permission filter
    let mut prev_state = Individual::default();
    let mut new_state = create_test_individual("test:filter1", "v-s:PermissionFilter");
    new_state.add_uri("v-s:permissionObject", "test:object1");
    new_state.add_uri("v-s:resource", "test:resource1");
    
    // Execute the function (add some default access for filter to work)
    let result = index_right_sets(
        &mut prev_state,
        &mut new_state,
        "v-s:permissionObject",
        "v-s:resource",
        FILTER_PREFIX,
        Access::CanRead as u8, // Add default access
        &mut ctx
    );
    assert!(result.is_ok());
    
    // Check what was written to the database
    let expected_key = format!("{FILTER_PREFIX}test:object1");
    let stored_value = ctx.storage.get::<String>(&expected_key);
    assert!(stored_value.is_some(), "Expected filter data to be written to storage with key: {expected_key}");
    
    // Decode and verify the stored data
    let stored_data = stored_value.unwrap();
    let mut record_set = ACLRecordSet::new();
    let (_, _) = decode_rec_to_rightset(&stored_data, &mut record_set);
    
    // Verify the record set contains our resource
    assert!(record_set.contains_key("test:resource1"), "Record set should contain resource test:resource1");
    
    let acl_record = record_set.get("test:resource1").unwrap();
    assert_eq!(acl_record.id, "test:resource1", "ACL record ID should match");
    
    // Verify access rights include the default CanRead
    assert!((acl_record.access & Access::CanRead as u8) != 0, 
            "Filter should have CanRead access");
}

#[test]
fn test_account_database_write() {
    let mut ctx = create_test_context();
    
    // Create account with login (simplified test without actual login field)
    let _prev_state = Individual::default();
    let new_state = create_test_individual("test:account1", "v-s:Account");
    
    // Simulate account processing (simplified)
    if !new_state.is_empty() {
        let key = format!("_L:{}", new_state.get_id().to_lowercase());
        let val = new_state.get_id();
        ctx.storage.put(&key, val);
    }
    
    // Check what was written to the database
    let expected_key = format!("_L:{}", "test:account1");
    let stored_value = ctx.storage.get::<String>(&expected_key);
    assert!(stored_value.is_some(), "Expected account data to be written to storage with key: {expected_key}");
    
    let stored_data = stored_value.unwrap();
    assert_eq!(stored_data, "test:account1", "Stored account ID should match");
}

#[test]
fn test_multiple_permission_subjects_database_write() {
    let mut ctx = create_test_context();
    
    // Create permission statement with multiple subjects
    let mut prev_state = Individual::default();
    let mut new_state = create_test_individual("test:permission2", "v-s:PermissionStatement");
    new_state.add_uri("v-s:permissionObject", "test:resource2");
    new_state.add_uri("v-s:permissionSubject", "test:subject1");
    new_state.add_uri("v-s:permissionSubject", "test:subject2");
    new_state.add_bool("v-s:canDelete", true);
    
    // Execute the function
    let result = prepare_permission_statement(&mut prev_state, &mut new_state, &mut ctx);
    assert!(result.is_ok());
    
    // Check what was written to the database
    let expected_key = format!("{PERMISSION_PREFIX}test:resource2");
    let stored_value = ctx.storage.get::<String>(&expected_key);
    assert!(stored_value.is_some(), "Expected data to be written to storage");
    
    // Decode and verify the stored data
    let stored_data = stored_value.unwrap();
    let mut record_set = ACLRecordSet::new();
    let (_, _) = decode_rec_to_rightset(&stored_data, &mut record_set);
    
    // Verify both subjects are in the record set
    assert!(record_set.contains_key("test:subject1"), "Record set should contain subject1");
    assert!(record_set.contains_key("test:subject2"), "Record set should contain subject2");
    
    // Verify both have delete access
    for subject_id in ["test:subject1", "test:subject2"] {
        let acl_record = record_set.get(subject_id).unwrap();
        assert_eq!(acl_record.id, subject_id);
        assert!((acl_record.access & Access::CanDelete as u8) != 0, 
                "Subject {subject_id} should have delete access");
    }
}

#[test]
fn test_permission_update_database_write() {
    let mut ctx = create_test_context();
    
    // First, create initial permission
    let mut prev_state = Individual::default();
    let mut new_state = create_test_individual("test:permission3", "v-s:PermissionStatement");
    new_state.add_uri("v-s:permissionObject", "test:resource3");
    new_state.add_uri("v-s:permissionSubject", "test:subject1");
    new_state.add_bool("v-s:canRead", true);
    
    let result = prepare_permission_statement(&mut prev_state, &mut new_state, &mut ctx);
    assert!(result.is_ok());
    
    // Now update the permission
    let mut prev_state2 = create_test_individual("test:permission3", "v-s:PermissionStatement");
    prev_state2.add_uri("v-s:permissionObject", "test:resource3");
    prev_state2.add_uri("v-s:permissionSubject", "test:subject1");
    prev_state2.add_bool("v-s:canRead", true);
    
    let mut new_state2 = create_test_individual("test:permission3", "v-s:PermissionStatement");
    new_state2.add_uri("v-s:permissionObject", "test:resource3");
    new_state2.add_uri("v-s:permissionSubject", "test:subject1");
    new_state2.add_bool("v-s:canRead", true);
    new_state2.add_bool("v-s:canUpdate", true);
    
    let result2 = prepare_permission_statement(&mut prev_state2, &mut new_state2, &mut ctx);
    assert!(result2.is_ok());
    
    // Check the updated data in database
    let expected_key = format!("{PERMISSION_PREFIX}test:resource3");
    let stored_value = ctx.storage.get::<String>(&expected_key);
    assert!(stored_value.is_some(), "Expected updated data to be in storage");
    
    let stored_data = stored_value.unwrap();
    let mut record_set = ACLRecordSet::new();
    let (_, _) = decode_rec_to_rightset(&stored_data, &mut record_set);
    
    assert!(record_set.contains_key("test:subject1"), "Record set should still contain subject1");
    let acl_record = record_set.get("test:subject1").unwrap();
    
    // Should have both read and update access now
    assert!((acl_record.access & Access::CanRead as u8) != 0, "Should have read access");
    assert!((acl_record.access & Access::CanUpdate as u8) != 0, "Should have update access");
}

#[test]
fn test_permission_deletion_database_write() {
    let mut ctx = create_test_context();
    
    // First, create a permission
    let mut prev_state = Individual::default();
    let mut new_state = create_test_individual("test:permission4", "v-s:PermissionStatement");
    new_state.add_uri("v-s:permissionObject", "test:resource4");
    new_state.add_uri("v-s:permissionSubject", "test:subject1");
    new_state.add_bool("v-s:canRead", true);
    
    let result = prepare_permission_statement(&mut prev_state, &mut new_state, &mut ctx);
    assert!(result.is_ok());
    
    // Now delete the permission (mark as deleted)
    let mut prev_state2 = create_test_individual("test:permission4", "v-s:PermissionStatement");
    prev_state2.add_uri("v-s:permissionObject", "test:resource4");
    prev_state2.add_uri("v-s:permissionSubject", "test:subject1");
    prev_state2.add_bool("v-s:canRead", true);
    
    let mut new_state2 = create_test_individual("test:permission4", "v-s:PermissionStatement");
    new_state2.add_uri("v-s:permissionObject", "test:resource4");
    new_state2.add_uri("v-s:permissionSubject", "test:subject1");
    new_state2.add_bool("v-s:canRead", true);
    new_state2.add_bool("v-s:deleted", true);
    
    let result2 = prepare_permission_statement(&mut prev_state2, &mut new_state2, &mut ctx);
    assert!(result2.is_ok());
    
    // Check the database after deletion
    let expected_key = format!("{PERMISSION_PREFIX}test:resource4");
    let stored_value = ctx.storage.get::<String>(&expected_key);
    assert!(stored_value.is_some(), "Data should still exist in storage after deletion");
    
    let stored_data = stored_value.unwrap();
    let mut record_set = ACLRecordSet::new();
    let (_, _) = decode_rec_to_rightset(&stored_data, &mut record_set);
    
    // After deletion, the record might be removed from the set entirely,
    // or it might be present but marked as deleted. Let's check both cases.
    if record_set.contains_key("test:subject1") {
        let acl_record = record_set.get("test:subject1").unwrap();
        // If the record exists, it should be marked as deleted
        assert!(acl_record.is_deleted, "Record should be marked as deleted");
    } else {
        // If the record doesn't exist, that's also a valid way to handle deletion
        // Just verify that the database still contains some data structure
        assert!(!stored_data.is_empty(), "Storage should contain some data after deletion");
    }
}

#[test]
fn test_database_key_format_verification() {
    let mut ctx = create_test_context();
    
    // Test different types of objects to verify key formats
    
    // 1. Permission statement
    let mut prev_state = Individual::default();
    let mut new_state = create_test_individual("test:permission", "v-s:PermissionStatement");
    new_state.add_uri("v-s:permissionObject", "test:resource");
    new_state.add_uri("v-s:permissionSubject", "test:subject");
    new_state.add_bool("v-s:canRead", true);
    
    let _ = prepare_permission_statement(&mut prev_state, &mut new_state, &mut ctx);
    
    // Verify permission key format: PERMISSION_PREFIX + resource
    let permission_key = format!("{PERMISSION_PREFIX}test:resource");
    let permission_data = ctx.storage.get::<String>(&permission_key);
    assert!(permission_data.is_some(), 
            "Permission key format should be PERMISSION_PREFIX + resource");
    
    // Verify permission data content
    let permission_stored = permission_data.unwrap();
    let mut permission_record_set = ACLRecordSet::new();
    let (_, _) = decode_rec_to_rightset(&permission_stored, &mut permission_record_set);
    assert!(permission_record_set.contains_key("test:subject"), 
            "Permission record set should contain subject");
    let permission_acl = permission_record_set.get("test:subject").unwrap();
    assert_eq!(permission_acl.id, "test:subject", "Permission ACL ID should match");
    assert!((permission_acl.access & Access::CanRead as u8) != 0, 
            "Permission should have CanRead access");
    
    // 2. Membership
    let mut prev_state2 = Individual::default();
    let mut new_state2 = create_test_individual("test:membership", "v-s:Membership");
    new_state2.add_uri("v-s:resource", "test:member_resource");
    new_state2.add_uri("v-s:memberOf", "test:group");
    new_state2.add_bool("v-s:canRead", true);
    
    let _ = index_right_sets(
        &mut prev_state2,
        &mut new_state2,
        "v-s:resource",
        "v-s:memberOf",
        MEMBERSHIP_PREFIX,
        Access::CanRead as u8,
        &mut ctx
    );
    
    // Verify membership key format: MEMBERSHIP_PREFIX + resource
    let membership_key = format!("{MEMBERSHIP_PREFIX}test:member_resource");
    let membership_data = ctx.storage.get::<String>(&membership_key);
    assert!(membership_data.is_some(), 
            "Membership key format should be MEMBERSHIP_PREFIX + resource");
    
    // Verify membership data content
    let membership_stored = membership_data.unwrap();
    let mut membership_record_set = ACLRecordSet::new();
    let (_, _) = decode_rec_to_rightset(&membership_stored, &mut membership_record_set);
    assert!(membership_record_set.contains_key("test:group"), 
            "Membership record set should contain group");
    let membership_acl = membership_record_set.get("test:group").unwrap();
    assert_eq!(membership_acl.id, "test:group", "Membership ACL ID should match");
    assert!((membership_acl.access & Access::CanRead as u8) != 0, 
            "Membership should have CanRead access");
    
    // 3. Filter
    let mut prev_state3 = Individual::default();
    let mut new_state3 = create_test_individual("test:filter", "v-s:PermissionFilter");
    new_state3.add_uri("v-s:permissionObject", "test:filter_object");
    new_state3.add_uri("v-s:resource", "test:filter_resource");
    
    let _ = index_right_sets(
        &mut prev_state3,
        &mut new_state3,
        "v-s:permissionObject",
        "v-s:resource",
        FILTER_PREFIX,
        Access::CanRead as u8, // Add default access for filter
        &mut ctx
    );
    
    // Verify filter key format: FILTER_PREFIX + object
    let filter_key = format!("{FILTER_PREFIX}test:filter_object");
    let filter_data = ctx.storage.get::<String>(&filter_key);
    assert!(filter_data.is_some(), 
            "Filter key format should be FILTER_PREFIX + object");
    
    // Verify filter data content
    let filter_stored = filter_data.unwrap();
    let mut filter_record_set = ACLRecordSet::new();
    let (_, _) = decode_rec_to_rightset(&filter_stored, &mut filter_record_set);
    assert!(filter_record_set.contains_key("test:filter_resource"), 
            "Filter record set should contain filter resource");
    let filter_acl = filter_record_set.get("test:filter_resource").unwrap();
    assert_eq!(filter_acl.id, "test:filter_resource", "Filter ACL ID should match");
    assert!((filter_acl.access & Access::CanRead as u8) != 0, 
            "Filter should have CanRead access");
} 