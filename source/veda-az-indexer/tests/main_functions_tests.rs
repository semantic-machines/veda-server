mod common;
use common::{create_test_context, create_test_individual, copy_individual_data};

use veda_az_indexer::common::*;

use v_individual_model::onto::individual::Individual;
use v_individual_model::onto::datatype::Lang;
use v_common::v_authorization::common::{Access, PERMISSION_PREFIX, MEMBERSHIP_PREFIX};
use v_common::v_authorization::record_formats::{decode_rec_to_rightset};
use v_common::v_authorization::ACLRecordSet;

#[test]
fn test_exclusive_marker() {
    let mut ctx = create_test_context();
    
    // Test with v-s:isExclusive = true
    let mut prev_state = Individual::default();
    let mut new_state = create_test_individual("test:permission1", "v-s:PermissionStatement");
    new_state.add_uri("v-s:permissionObject", "test:resource1");
    new_state.add_uri("v-s:permissionSubject", "test:subject1");
    new_state.add_bool("v-s:canRead", true);
    new_state.add_bool("v-s:isExclusive", true);
    
    let result = prepare_permission_statement(&mut prev_state, &mut new_state, &mut ctx);
    assert!(result.is_ok());
    
    // Check that marker is set correctly
    let expected_key = format!("{PERMISSION_PREFIX}test:resource1");
    let stored_value = ctx.storage.get(&expected_key);
    assert!(stored_value.is_some());
    
    let stored_data = stored_value.unwrap();
    let mut record_set = ACLRecordSet::new();
    let (_, _) = decode_rec_to_rightset(&stored_data, &mut record_set);
    
    let acl_record = record_set.get("test:subject1").unwrap();
    assert_eq!(acl_record.marker as u8, v_common::v_authorization::common::M_IS_EXCLUSIVE as u8);
}

#[test]
fn test_ignore_exclusive_marker() {
    let mut ctx = create_test_context();
    
    // Test with v-s:ignoreExclusive = true
    let mut prev_state = Individual::default();
    let mut new_state = create_test_individual("test:permission2", "v-s:PermissionStatement");
    new_state.add_uri("v-s:permissionObject", "test:resource2");
    new_state.add_uri("v-s:permissionSubject", "test:subject2");
    new_state.add_bool("v-s:canRead", true);
    new_state.add_bool("v-s:ignoreExclusive", true);
    
    let result = prepare_permission_statement(&mut prev_state, &mut new_state, &mut ctx);
    assert!(result.is_ok());
    
    // Check that marker is set correctly
    let expected_key = format!("{PERMISSION_PREFIX}test:resource2");
    let stored_value = ctx.storage.get(&expected_key);
    assert!(stored_value.is_some());
    
    let stored_data = stored_value.unwrap();
    let mut record_set = ACLRecordSet::new();
    let (_, _) = decode_rec_to_rightset(&stored_data, &mut record_set);
    
    let acl_record = record_set.get("test:subject2").unwrap();
    assert_eq!(acl_record.marker as u8, v_common::v_authorization::common::M_IGNORE_EXCLUSIVE as u8);
}

#[test]
fn test_no_exclusive_marker() {
    let mut ctx = create_test_context();
    
    // Test without exclusive flags
    let mut prev_state = Individual::default();
    let mut new_state = create_test_individual("test:permission3", "v-s:PermissionStatement");
    new_state.add_uri("v-s:permissionObject", "test:resource3");
    new_state.add_uri("v-s:permissionSubject", "test:subject3");
    new_state.add_bool("v-s:canRead", true);
    
    let result = prepare_permission_statement(&mut prev_state, &mut new_state, &mut ctx);
    assert!(result.is_ok());
    
    // Check that marker is 0
    let expected_key = format!("{PERMISSION_PREFIX}test:resource3");
    let stored_value = ctx.storage.get(&expected_key);
    assert!(stored_value.is_some());
    
    let stored_data = stored_value.unwrap();
    let mut record_set = ACLRecordSet::new();
    let (_, _) = decode_rec_to_rightset(&stored_data, &mut record_set);
    
    let acl_record = record_set.get("test:subject3").unwrap();
    assert_eq!(acl_record.marker, 0 as char);
}

#[test]
fn test_object_restoration() {
    let mut ctx = create_test_context();
    
    // First create and delete an object
    let mut prev_state1 = Individual::default();
    let mut new_state1 = create_test_individual("test:permission4", "v-s:PermissionStatement");
    new_state1.add_uri("v-s:permissionObject", "test:resource4");
    new_state1.add_uri("v-s:permissionSubject", "test:subject4");
    new_state1.add_bool("v-s:canRead", true);
    
    let result1 = prepare_permission_statement(&mut prev_state1, &mut new_state1, &mut ctx);
    assert!(result1.is_ok());
    
    // Now mark it as deleted
    let mut prev_state2 = copy_individual_data(&mut new_state1);
    let mut new_state2 = create_test_individual("test:permission4", "v-s:PermissionStatement");
    new_state2.add_uri("v-s:permissionObject", "test:resource4");
    new_state2.add_uri("v-s:permissionSubject", "test:subject4");
    new_state2.add_bool("v-s:canRead", true);
    new_state2.add_bool("v-s:deleted", true);
    
    let result2 = prepare_permission_statement(&mut prev_state2, &mut new_state2, &mut ctx);
    assert!(result2.is_ok());
    
    // Now restore it (deleted = false after being deleted = true)
    let mut prev_state3 = copy_individual_data(&mut new_state2);
    let mut new_state3 = create_test_individual("test:permission4", "v-s:PermissionStatement");
    new_state3.add_uri("v-s:permissionObject", "test:resource4");
    new_state3.add_uri("v-s:permissionSubject", "test:subject4");
    new_state3.add_bool("v-s:canRead", true);
    new_state3.add_bool("v-s:canUpdate", true);
    new_state3.add_bool("v-s:deleted", false);
    
    let result3 = prepare_permission_statement(&mut prev_state3, &mut new_state3, &mut ctx);
    assert!(result3.is_ok());
    
    // Check that the object is restored and has updated permissions
    let expected_key = format!("{PERMISSION_PREFIX}test:resource4");
    let stored_value = ctx.storage.get(&expected_key);
    assert!(stored_value.is_some());
    
    let stored_data = stored_value.unwrap();
    let mut record_set = ACLRecordSet::new();
    let (_, _) = decode_rec_to_rightset(&stored_data, &mut record_set);
    
    assert!(record_set.contains_key("test:subject4"));
    let acl_record = record_set.get("test:subject4").unwrap();
    assert!(!acl_record.is_deleted, "Record should not be deleted after restoration");
    assert!((acl_record.access & Access::CanRead as u8) != 0, "Should have read access");
    assert!((acl_record.access & Access::CanUpdate as u8) != 0, "Should have update access");
}

#[test]
fn test_membership_with_multiple_resources() {
    let mut ctx = create_test_context();
    
    // Create membership with multiple resources
    let mut prev_state = Individual::default();
    let mut new_state = create_test_individual("test:membership1", "v-s:Membership");
    new_state.add_uri("v-s:resource", "test:res1");
    new_state.add_uri("v-s:resource", "test:res2");
    new_state.add_uri("v-s:memberOf", "test:group1");
    new_state.add_bool("v-s:canRead", true);
    
    let result = index_right_sets(
        &mut prev_state,
        &mut new_state,
        "v-s:resource",
        "v-s:memberOf",
        MEMBERSHIP_PREFIX,
        Access::CanRead as u8,
        &mut ctx
    );
    assert!(result.is_ok());
    
    // Check that both resources have the membership
    for resource in ["test:res1", "test:res2"] {
        let expected_key = format!("{MEMBERSHIP_PREFIX}{resource}");
        let stored_value = ctx.storage.get(&expected_key);
        assert!(stored_value.is_some(), "Membership should be stored for {resource}");
        
        let stored_data = stored_value.unwrap();
        let mut record_set = ACLRecordSet::new();
        let (_, _) = decode_rec_to_rightset(&stored_data, &mut record_set);
        
        assert!(record_set.contains_key("test:group1"), "Group should be in record set for {resource}");
    }
}

#[test]
fn test_update_with_resource_change() {
    let mut ctx = create_test_context();
    
    // Create initial permission
    let mut prev_state1 = Individual::default();
    let mut new_state1 = create_test_individual("test:permission5", "v-s:PermissionStatement");
    new_state1.add_uri("v-s:permissionObject", "test:oldResource");
    new_state1.add_uri("v-s:permissionSubject", "test:subject5");
    new_state1.add_bool("v-s:canRead", true);
    
    let result1 = prepare_permission_statement(&mut prev_state1, &mut new_state1, &mut ctx);
    assert!(result1.is_ok());
    
    // Update to change resource
    let mut prev_state2 = copy_individual_data(&mut new_state1);
    let mut new_state2 = create_test_individual("test:permission5", "v-s:PermissionStatement");
    new_state2.add_uri("v-s:permissionObject", "test:newResource");
    new_state2.add_uri("v-s:permissionSubject", "test:subject5");
    new_state2.add_bool("v-s:canRead", true);
    
    let result2 = prepare_permission_statement(&mut prev_state2, &mut new_state2, &mut ctx);
    assert!(result2.is_ok());
    
    // Check that new resource has the permission
    let new_key = format!("{PERMISSION_PREFIX}test:newResource");
    let new_stored = ctx.storage.get(&new_key);
    assert!(new_stored.is_some(), "New resource should have permission");
    
    let new_data = new_stored.unwrap();
    let mut new_record_set = ACLRecordSet::new();
    let (_, _) = decode_rec_to_rightset(&new_data, &mut new_record_set);
    assert!(new_record_set.contains_key("test:subject5"));
    
    // Check that old resource still exists but subject should be marked deleted
    let old_key = format!("{PERMISSION_PREFIX}test:oldResource");
    let old_stored = ctx.storage.get(&old_key);
    assert!(old_stored.is_some(), "Old resource should still have data");
    
    let old_data = old_stored.unwrap();
    let mut old_record_set = ACLRecordSet::new();
    let (_, _) = decode_rec_to_rightset(&old_data, &mut old_record_set);
    
    if old_record_set.contains_key("test:subject5") {
        let acl_record = old_record_set.get("test:subject5").unwrap();
        assert!(acl_record.is_deleted, "Old resource subject should be marked as deleted");
    }
}

#[test]
fn test_use_filter_field() {
    let mut ctx = create_test_context();
    
    // Create membership with useFilter
    let mut prev_state = Individual::default();
    let mut new_state = create_test_individual("test:membership2", "v-s:Membership");
    new_state.add_uri("v-s:resource", "test:resource5");
    new_state.add_uri("v-s:memberOf", "test:group2");
    new_state.add_string("v-s:useFilter", "filter1:", Lang::none());
    new_state.add_bool("v-s:canRead", true);
    
    let result = index_right_sets(
        &mut prev_state,
        &mut new_state,
        "v-s:resource",
        "v-s:memberOf",
        MEMBERSHIP_PREFIX,
        Access::CanRead as u8,
        &mut ctx
    );
    assert!(result.is_ok());
    
    // Check that the key includes the filter
    let expected_key = format!("{MEMBERSHIP_PREFIX}filter1:test:resource5");
    let stored_value = ctx.storage.get(&expected_key);
    assert!(stored_value.is_some(), "Membership with filter should be stored");
}

#[test]
fn test_multiple_subjects_removal() {
    let mut ctx = create_test_context();
    
    // Create permission with 3 subjects
    let mut prev_state1 = Individual::default();
    let mut new_state1 = create_test_individual("test:permission6", "v-s:PermissionStatement");
    new_state1.add_uri("v-s:permissionObject", "test:resource6");
    new_state1.add_uri("v-s:permissionSubject", "test:subj1");
    new_state1.add_uri("v-s:permissionSubject", "test:subj2");
    new_state1.add_uri("v-s:permissionSubject", "test:subj3");
    new_state1.add_bool("v-s:canRead", true);
    
    let result1 = prepare_permission_statement(&mut prev_state1, &mut new_state1, &mut ctx);
    assert!(result1.is_ok());
    
    // Update to remove one subject
    let mut prev_state2 = copy_individual_data(&mut new_state1);
    let mut new_state2 = create_test_individual("test:permission6", "v-s:PermissionStatement");
    new_state2.add_uri("v-s:permissionObject", "test:resource6");
    new_state2.add_uri("v-s:permissionSubject", "test:subj1");
    new_state2.add_uri("v-s:permissionSubject", "test:subj3");
    new_state2.add_bool("v-s:canRead", true);
    
    let result2 = prepare_permission_statement(&mut prev_state2, &mut new_state2, &mut ctx);
    assert!(result2.is_ok());
    
    // Check the state
    let expected_key = format!("{PERMISSION_PREFIX}test:resource6");
    let stored_value = ctx.storage.get(&expected_key);
    assert!(stored_value.is_some());
    
    let stored_data = stored_value.unwrap();
    let mut record_set = ACLRecordSet::new();
    let (_, _) = decode_rec_to_rightset(&stored_data, &mut record_set);
    
    // subj1 and subj3 should be active
    assert!(record_set.contains_key("test:subj1"));
    assert!(record_set.contains_key("test:subj3"));
    
    let acl1 = record_set.get("test:subj1").unwrap();
    let acl3 = record_set.get("test:subj3").unwrap();
    assert!(!acl1.is_deleted);
    assert!(!acl3.is_deleted);
    
    // subj2 should be marked deleted or not present with active access
    if record_set.contains_key("test:subj2") {
        let acl2 = record_set.get("test:subj2").unwrap();
        assert!(acl2.is_deleted, "Removed subject should be marked as deleted");
    }
}

#[test]
fn test_empty_access_uses_default() {
    let mut ctx = create_test_context();
    
    // Create membership without explicit permissions (should use default)
    let mut prev_state = Individual::default();
    let mut new_state = create_test_individual("test:membership3", "v-s:Membership");
    new_state.add_uri("v-s:resource", "test:resource7");
    new_state.add_uri("v-s:memberOf", "test:group3");
    // No explicit permissions set
    
    let default_access = Access::CanCreate as u8 | Access::CanRead as u8 | Access::CanUpdate as u8 | Access::CanDelete as u8;
    
    let result = index_right_sets(
        &mut prev_state,
        &mut new_state,
        "v-s:resource",
        "v-s:memberOf",
        MEMBERSHIP_PREFIX,
        default_access,
        &mut ctx
    );
    assert!(result.is_ok());
    
    // Check that default access was applied
    let expected_key = format!("{MEMBERSHIP_PREFIX}test:resource7");
    let stored_value = ctx.storage.get(&expected_key);
    assert!(stored_value.is_some());
    
    let stored_data = stored_value.unwrap();
    let mut record_set = ACLRecordSet::new();
    let (_, _) = decode_rec_to_rightset(&stored_data, &mut record_set);
    
    let acl_record = record_set.get("test:group3").unwrap();
    assert_eq!(acl_record.access, default_access, "Should use default access when no permissions specified");
}
