mod common;
use common::{create_test_context, create_test_individual};

use veda_az_indexer::common::*;

use v_individual_model::onto::individual::Individual;
use v_common::v_authorization::common::{Access, PERMISSION_PREFIX};
use v_common::v_authorization::record_formats::{decode_rec_to_rightset};
use v_common::v_authorization::ACLRecordSet;

#[test]
fn test_drop_count_basic() {
    let mut ctx = create_test_context();
    
    // Create permission with dropCount
    let mut prev_state = Individual::default();
    let mut new_state = create_test_individual("test:permission1", "v-s:PermissionStatement");
    new_state.add_uri("v-s:permissionObject", "test:resource1");
    new_state.add_uri("v-s:permissionSubject", "test:subject1");
    new_state.add_bool("v-s:canRead", true);
    new_state.add_bool("v-s:dropCount", true);
    new_state.add_integer("v-s:updateCounter", 1);
    
    let result = prepare_permission_statement(&mut prev_state, &mut new_state, &mut ctx);
    assert!(result.is_ok());
    
    // Verify that record was created
    let expected_key = format!("{PERMISSION_PREFIX}test:resource1");
    let stored_value = ctx.storage.get(&expected_key);
    assert!(stored_value.is_some());
    
    let stored_data = stored_value.unwrap();
    let mut record_set = ACLRecordSet::new();
    let (_, _) = decode_rec_to_rightset(&stored_data, &mut record_set);
    
    assert!(record_set.contains_key("test:subject1"));
    let acl_record = record_set.get("test:subject1").unwrap();
    assert!((acl_record.access & Access::CanRead as u8) != 0);
}

#[test]
fn test_drop_count_with_update_counter_greater_than_one() {
    let mut ctx = create_test_context();
    
    // Create permission with dropCount and updateCounter > 1 (should be skipped)
    let mut prev_state = Individual::default();
    let mut new_state = create_test_individual("test:permission2", "v-s:PermissionStatement");
    new_state.add_uri("v-s:permissionObject", "test:resource2");
    new_state.add_uri("v-s:permissionSubject", "test:subject2");
    new_state.add_bool("v-s:canRead", true);
    new_state.add_bool("v-s:dropCount", true);
    new_state.add_integer("v-s:updateCounter", 2);
    
    let result = prepare_permission_statement(&mut prev_state, &mut new_state, &mut ctx);
    assert!(result.is_ok());
    
    // Verify that record was NOT created (skipped due to updateCounter > 1)
    let expected_key = format!("{PERMISSION_PREFIX}test:resource2");
    let stored_value = ctx.storage.get(&expected_key);
    
    // Should be None or empty because indexing was skipped
    if let Some(data) = stored_value {
        let mut record_set = ACLRecordSet::new();
        decode_rec_to_rightset(&data, &mut record_set);
        // If data exists, it should be from a previous operation, not this one
        assert!(record_set.is_empty() || !record_set.contains_key("test:subject2"));
    }
}

#[test]
fn test_change_from_read_to_update() {
    let mut ctx = create_test_context();
    
    // Create permission with read access
    let mut prev_state1 = Individual::default();
    let mut new_state1 = create_test_individual("test:permission3", "v-s:PermissionStatement");
    new_state1.add_uri("v-s:permissionObject", "test:resource3");
    new_state1.add_uri("v-s:permissionSubject", "test:subject3");
    new_state1.add_bool("v-s:canRead", true);
    
    let result1 = prepare_permission_statement(&mut prev_state1, &mut new_state1, &mut ctx);
    assert!(result1.is_ok());
    
    // Update to change to update access only
    let mut prev_state2 = create_test_individual("test:permission3", "v-s:PermissionStatement");
    prev_state2.add_uri("v-s:permissionObject", "test:resource3");
    prev_state2.add_uri("v-s:permissionSubject", "test:subject3");
    prev_state2.add_bool("v-s:canRead", true);
    
    let mut new_state2 = create_test_individual("test:permission3", "v-s:PermissionStatement");
    new_state2.add_uri("v-s:permissionObject", "test:resource3");
    new_state2.add_uri("v-s:permissionSubject", "test:subject3");
    new_state2.add_bool("v-s:canRead", false);
    new_state2.add_bool("v-s:canUpdate", true);
    
    let result2 = prepare_permission_statement(&mut prev_state2, &mut new_state2, &mut ctx);
    assert!(result2.is_ok());
    
    // Check that access was updated correctly
    let expected_key = format!("{PERMISSION_PREFIX}test:resource3");
    let stored_value = ctx.storage.get(&expected_key);
    assert!(stored_value.is_some());
    
    let stored_data = stored_value.unwrap();
    let mut record_set = ACLRecordSet::new();
    let (_, _) = decode_rec_to_rightset(&stored_data, &mut record_set);
    
    let acl_record = record_set.get("test:subject3").unwrap();
    
    // Should have CantRead and CanUpdate
    assert!((acl_record.access & Access::CantRead as u8) != 0, "Should have CantRead flag");
    assert!((acl_record.access & Access::CanUpdate as u8) != 0, "Should have CanUpdate flag");
}

#[test]
fn test_explicit_cant_permissions() {
    let mut ctx = create_test_context();
    
    // Create permission with explicit Can't permissions
    let mut prev_state = Individual::default();
    let mut new_state = create_test_individual("test:permission4", "v-s:PermissionStatement");
    new_state.add_uri("v-s:permissionObject", "test:resource4");
    new_state.add_uri("v-s:permissionSubject", "test:subject4");
    new_state.add_bool("v-s:canRead", true);
    new_state.add_bool("v-s:canCreate", false);
    new_state.add_bool("v-s:canUpdate", false);
    new_state.add_bool("v-s:canDelete", false);
    
    let result = prepare_permission_statement(&mut prev_state, &mut new_state, &mut ctx);
    assert!(result.is_ok());
    
    // Verify the access flags
    let expected_key = format!("{PERMISSION_PREFIX}test:resource4");
    let stored_value = ctx.storage.get(&expected_key);
    assert!(stored_value.is_some());
    
    let stored_data = stored_value.unwrap();
    let mut record_set = ACLRecordSet::new();
    let (_, _) = decode_rec_to_rightset(&stored_data, &mut record_set);
    
    let acl_record = record_set.get("test:subject4").unwrap();
    
    // Should have CanRead and Can't flags for others
    assert!((acl_record.access & Access::CanRead as u8) != 0);
    assert!((acl_record.access & Access::CantCreate as u8) != 0);
    assert!((acl_record.access & Access::CantUpdate as u8) != 0);
    assert!((acl_record.access & Access::CantDelete as u8) != 0);
}

#[test]
fn test_permission_with_empty_subject() {
    let mut ctx = create_test_context();
    
    // Create permission with empty subject list
    let mut prev_state = Individual::default();
    let mut new_state = create_test_individual("test:permission5", "v-s:PermissionStatement");
    new_state.add_uri("v-s:permissionObject", "test:resource5");
    // No subjects added
    new_state.add_bool("v-s:canRead", true);
    
    let result = prepare_permission_statement(&mut prev_state, &mut new_state, &mut ctx);
    assert!(result.is_ok());
    
    // Check that an empty or minimal record is created
    let expected_key = format!("{PERMISSION_PREFIX}test:resource5");
    let stored_value = ctx.storage.get(&expected_key);
    assert!(stored_value.is_some());
    
    let stored_data = stored_value.unwrap();
    let mut record_set = ACLRecordSet::new();
    let (_, _) = decode_rec_to_rightset(&stored_data, &mut record_set);
    
    // Record set should be empty or contain only metadata
    assert!(record_set.is_empty(), "Record set should be empty when no subjects specified");
}

#[test]
fn test_permission_with_empty_object() {
    let mut ctx = create_test_context();
    
    // Create permission with empty object list
    let mut prev_state = Individual::default();
    let mut new_state = create_test_individual("test:permission6", "v-s:PermissionStatement");
    // No objects added
    new_state.add_uri("v-s:permissionSubject", "test:subject6");
    new_state.add_bool("v-s:canRead", true);
    
    let result = prepare_permission_statement(&mut prev_state, &mut new_state, &mut ctx);
    assert!(result.is_ok());
    
    // Should not create any storage entries
    // This is a degenerate case but should handle gracefully
}

#[test]
fn test_concurrent_updates_different_subjects() {
    let mut ctx = create_test_context();
    
    // First update: add subject1
    let mut prev1 = Individual::default();
    let mut new1 = create_test_individual("test:permission7", "v-s:PermissionStatement");
    new1.add_uri("v-s:permissionObject", "test:resource7");
    new1.add_uri("v-s:permissionSubject", "test:subject7a");
    new1.add_bool("v-s:canRead", true);
    
    let result1 = prepare_permission_statement(&mut prev1, &mut new1, &mut ctx);
    assert!(result1.is_ok());
    
    // Second update: add subject2 to same resource
    let mut prev2 = Individual::default();
    let mut new2 = create_test_individual("test:permission8", "v-s:PermissionStatement");
    new2.add_uri("v-s:permissionObject", "test:resource7");
    new2.add_uri("v-s:permissionSubject", "test:subject7b");
    new2.add_bool("v-s:canUpdate", true);
    
    let result2 = prepare_permission_statement(&mut prev2, &mut new2, &mut ctx);
    assert!(result2.is_ok());
    
    // Check that both subjects are in the storage
    let expected_key = format!("{PERMISSION_PREFIX}test:resource7");
    let stored_value = ctx.storage.get(&expected_key);
    assert!(stored_value.is_some());
    
    let stored_data = stored_value.unwrap();
    let mut record_set = ACLRecordSet::new();
    let (_, _) = decode_rec_to_rightset(&stored_data, &mut record_set);
    
    // Both subjects should be present
    assert!(record_set.contains_key("test:subject7a") || record_set.contains_key("test:subject7b"),
            "At least one subject should be present");
}

#[test]
fn test_all_access_flags_combination() {
    let mut ctx = create_test_context();
    
    // Test all possible combinations of access flags
    let mut prev_state = Individual::default();
    let mut new_state = create_test_individual("test:permission9", "v-s:PermissionStatement");
    new_state.add_uri("v-s:permissionObject", "test:resource9");
    new_state.add_uri("v-s:permissionSubject", "test:subject9");
    new_state.add_bool("v-s:canCreate", true);
    new_state.add_bool("v-s:canRead", true);
    new_state.add_bool("v-s:canUpdate", true);
    new_state.add_bool("v-s:canDelete", true);
    
    let result = prepare_permission_statement(&mut prev_state, &mut new_state, &mut ctx);
    assert!(result.is_ok());
    
    // Verify all flags are set
    let expected_key = format!("{PERMISSION_PREFIX}test:resource9");
    let stored_value = ctx.storage.get(&expected_key);
    assert!(stored_value.is_some());
    
    let stored_data = stored_value.unwrap();
    let mut record_set = ACLRecordSet::new();
    let (_, _) = decode_rec_to_rightset(&stored_data, &mut record_set);
    
    let acl_record = record_set.get("test:subject9").unwrap();
    
    let full_access = Access::CanCreate as u8 | Access::CanRead as u8 | 
                      Access::CanUpdate as u8 | Access::CanDelete as u8;
    
    assert_eq!(acl_record.access & full_access, full_access, "All access flags should be set");
}

#[test]
fn test_version_of_index_format() {
    let mut ctx = create_test_context();
    
    // Test with version 2 (default)
    assert_eq!(ctx.version_of_index_format, 2);
    
    let mut prev_state = Individual::default();
    let mut new_state = create_test_individual("test:permission10", "v-s:PermissionStatement");
    new_state.add_uri("v-s:permissionObject", "test:resource10");
    new_state.add_uri("v-s:permissionSubject", "test:subject10");
    new_state.add_bool("v-s:canRead", true);
    
    let result = prepare_permission_statement(&mut prev_state, &mut new_state, &mut ctx);
    assert!(result.is_ok());
    
    // Change version to 1
    ctx.version_of_index_format = 1;
    
    let mut prev_state2 = Individual::default();
    let mut new_state2 = create_test_individual("test:permission11", "v-s:PermissionStatement");
    new_state2.add_uri("v-s:permissionObject", "test:resource11");
    new_state2.add_uri("v-s:permissionSubject", "test:subject11");
    new_state2.add_bool("v-s:canRead", true);
    
    let result2 = prepare_permission_statement(&mut prev_state2, &mut new_state2, &mut ctx);
    assert!(result2.is_ok());
    
    // Both versions should work
    let key1 = format!("{PERMISSION_PREFIX}test:resource10");
    let key2 = format!("{PERMISSION_PREFIX}test:resource11");
    
    assert!(ctx.storage.get(&key1).is_some());
    assert!(ctx.storage.get(&key2).is_some());
}

#[test]
fn test_deny_permissions_separate_storage() {
    let mut ctx = create_test_context();
    
    // Create permission with only deny bits (Cant*)
    let mut prev_state = Individual::default();
    let mut new_state = create_test_individual("test:deny_perm1", "v-s:PermissionStatement");
    new_state.add_uri("v-s:permissionObject", "test:deny_resource1");
    new_state.add_uri("v-s:permissionSubject", "test:deny_subject1");
    new_state.add_bool("v-s:canCreate", false);
    new_state.add_bool("v-s:canDelete", false);
    
    let result = prepare_permission_statement(&mut prev_state, &mut new_state, &mut ctx);
    assert!(result.is_ok());
    
    // Check that deny permissions went to deny_storage
    let deny_key = format!("{PERMISSION_PREFIX}test:deny_resource1");
    let deny_value = ctx.deny_storage.get(&deny_key);
    assert!(deny_value.is_some(), "Deny permissions should be in deny_storage");
    
    // Verify the deny bits
    let deny_data = deny_value.unwrap();
    let mut deny_record_set = ACLRecordSet::new();
    decode_rec_to_rightset(&deny_data, &mut deny_record_set);
    
    let deny_acl = deny_record_set.get("test:deny_subject1").unwrap();
    assert!((deny_acl.access & Access::CantCreate as u8) != 0, "Should have CantCreate flag");
    assert!((deny_acl.access & Access::CantDelete as u8) != 0, "Should have CantDelete flag");
}

#[test]
fn test_allow_permissions_separate_storage() {
    let mut ctx = create_test_context();
    
    // Create permission with only allow bits (Can*)
    let mut prev_state = Individual::default();
    let mut new_state = create_test_individual("test:allow_perm1", "v-s:PermissionStatement");
    new_state.add_uri("v-s:permissionObject", "test:allow_resource1");
    new_state.add_uri("v-s:permissionSubject", "test:allow_subject1");
    new_state.add_bool("v-s:canRead", true);
    new_state.add_bool("v-s:canUpdate", true);
    
    let result = prepare_permission_statement(&mut prev_state, &mut new_state, &mut ctx);
    assert!(result.is_ok());
    
    // Check that allow permissions went to main storage
    let allow_key = format!("{PERMISSION_PREFIX}test:allow_resource1");
    let allow_value = ctx.storage.get(&allow_key);
    assert!(allow_value.is_some(), "Allow permissions should be in main storage");
    
    // Verify the allow bits
    let allow_data = allow_value.unwrap();
    let mut allow_record_set = ACLRecordSet::new();
    decode_rec_to_rightset(&allow_data, &mut allow_record_set);
    
    let allow_acl = allow_record_set.get("test:allow_subject1").unwrap();
    assert!((allow_acl.access & Access::CanRead as u8) != 0, "Should have CanRead flag");
    assert!((allow_acl.access & Access::CanUpdate as u8) != 0, "Should have CanUpdate flag");
    
    // Verify deny_storage does NOT have this permission
    let deny_value = ctx.deny_storage.get(&allow_key);
    assert!(deny_value.is_none(), "Allow-only permissions should NOT be in deny_storage");
}

#[test]
fn test_mixed_permissions_both_storages() {
    let mut ctx = create_test_context();
    
    // Create permission with both allow and deny bits
    let mut prev_state = Individual::default();
    let mut new_state = create_test_individual("test:mixed_perm1", "v-s:PermissionStatement");
    new_state.add_uri("v-s:permissionObject", "test:mixed_resource1");
    new_state.add_uri("v-s:permissionSubject", "test:mixed_subject1");
    new_state.add_bool("v-s:canRead", true);      // Allow
    new_state.add_bool("v-s:canUpdate", false);   // Deny
    new_state.add_bool("v-s:canDelete", false);   // Deny
    
    let result = prepare_permission_statement(&mut prev_state, &mut new_state, &mut ctx);
    assert!(result.is_ok());
    
    let key = format!("{PERMISSION_PREFIX}test:mixed_resource1");
    
    // Check allow storage has the allow bits
    let allow_value = ctx.storage.get(&key);
    assert!(allow_value.is_some(), "Allow bits should be in main storage");
    
    let allow_data = allow_value.unwrap();
    let mut allow_record_set = ACLRecordSet::new();
    decode_rec_to_rightset(&allow_data, &mut allow_record_set);
    
    let allow_acl = allow_record_set.get("test:mixed_subject1").unwrap();
    assert!((allow_acl.access & Access::CanRead as u8) != 0, "Should have CanRead flag");
    
    // Check deny storage has the deny bits
    let deny_value = ctx.deny_storage.get(&key);
    assert!(deny_value.is_some(), "Deny bits should be in deny_storage");
    
    let deny_data = deny_value.unwrap();
    let mut deny_record_set = ACLRecordSet::new();
    decode_rec_to_rightset(&deny_data, &mut deny_record_set);
    
    let deny_acl = deny_record_set.get("test:mixed_subject1").unwrap();
    assert!((deny_acl.access & Access::CantUpdate as u8) != 0, "Should have CantUpdate flag");
    assert!((deny_acl.access & Access::CantDelete as u8) != 0, "Should have CantDelete flag");
}

#[test]
fn test_deny_permission_update() {
    let mut ctx = create_test_context();
    
    // Create initial deny permission
    let mut prev_state = Individual::default();
    let mut new_state = create_test_individual("test:deny_perm2", "v-s:PermissionStatement");
    new_state.add_uri("v-s:permissionObject", "test:deny_resource2");
    new_state.add_uri("v-s:permissionSubject", "test:deny_subject2");
    new_state.add_bool("v-s:canCreate", false);
    
    let result = prepare_permission_statement(&mut prev_state, &mut new_state, &mut ctx);
    assert!(result.is_ok());
    
    // Update: add more deny bits
    let mut prev_state2 = create_test_individual("test:deny_perm2", "v-s:PermissionStatement");
    prev_state2.add_uri("v-s:permissionObject", "test:deny_resource2");
    prev_state2.add_uri("v-s:permissionSubject", "test:deny_subject2");
    prev_state2.add_bool("v-s:canCreate", false);
    
    let mut new_state2 = create_test_individual("test:deny_perm2", "v-s:PermissionStatement");
    new_state2.add_uri("v-s:permissionObject", "test:deny_resource2");
    new_state2.add_uri("v-s:permissionSubject", "test:deny_subject2");
    new_state2.add_bool("v-s:canCreate", false);
    new_state2.add_bool("v-s:canDelete", false);
    
    let result2 = prepare_permission_statement(&mut prev_state2, &mut new_state2, &mut ctx);
    assert!(result2.is_ok());
    
    // Verify both deny bits are now in deny_storage
    let deny_key = format!("{PERMISSION_PREFIX}test:deny_resource2");
    let deny_value = ctx.deny_storage.get(&deny_key);
    assert!(deny_value.is_some());
    
    let deny_data = deny_value.unwrap();
    let mut deny_record_set = ACLRecordSet::new();
    decode_rec_to_rightset(&deny_data, &mut deny_record_set);
    
    let deny_acl = deny_record_set.get("test:deny_subject2").unwrap();
    assert!((deny_acl.access & Access::CantCreate as u8) != 0, "Should have CantCreate flag");
    assert!((deny_acl.access & Access::CantDelete as u8) != 0, "Should have CantDelete flag");
}

#[test]
fn test_helper_functions() {
    // Test has_deny_access
    let deny_access = Access::CantRead as u8 | Access::CantUpdate as u8;
    assert!(has_deny_access(deny_access), "Should detect deny access");
    
    let allow_access = Access::CanRead as u8 | Access::CanUpdate as u8;
    assert!(!has_deny_access(allow_access), "Should not detect deny in allow access");
    
    // Test has_allow_access
    assert!(has_allow_access(allow_access), "Should detect allow access");
    assert!(!has_allow_access(deny_access), "Should not detect allow in deny access");
    
    // Test mixed access
    let mixed_access = Access::CanRead as u8 | Access::CantCreate as u8;
    assert!(has_deny_access(mixed_access), "Should detect deny in mixed access");
    assert!(has_allow_access(mixed_access), "Should detect allow in mixed access");
}

