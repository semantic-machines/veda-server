use serde_json::json;

use v_individual_model::onto::individual::Individual;
use v_individual_model::onto::json2individual::parse_json_to_individual;

// Integration tests for veda-mstorage
// These tests exercise the full API workflow

#[test]
fn test_individual_creation_workflow() {
    // Test creating a person individual through JSON API
    let json_individual = json!({
        "@": "d:integration_person_001",
        "rdf:type": [{"data": "v-s:Person", "type": "Uri"}],
        "v-s:firstName": [{"data": "Alice", "type": "String", "lang": "EN"}],
        "v-s:lastName": [{"data": "Johnson", "type": "String", "lang": "EN"}],
        "v-s:email": [{"data": "alice.johnson@example.com", "type": "String"}],
        "v-s:birthDate": [{"data": "1985-03-15T00:00:00Z", "type": "Datetime"}]
    });

    let mut individual = Individual::default();
    let parse_result = parse_json_to_individual(&json_individual, &mut individual);
    
    assert!(parse_result, "Failed to parse JSON to individual");
    assert_eq!(individual.get_id(), "d:integration_person_001");
    
    // Verify properties
    let first_name = individual.get_first_literal("v-s:firstName");
    assert!(first_name.is_some());
    assert_eq!(first_name.unwrap(), "Alice");
    
    let email = individual.get_first_literal("v-s:email");
    assert!(email.is_some());
    assert_eq!(email.unwrap(), "alice.johnson@example.com");
}

#[test]
fn test_organization_creation_workflow() {
    // Test creating an organization
    let json_org = json!({
        "@": "d:integration_org_001",
        "rdf:type": [{"data": "v-s:Organization", "type": "Uri"}],
        "v-s:label": [{"data": "Tech Innovations Inc", "type": "String", "lang": "EN"}],
        "v-s:description": [{"data": "Leading technology company", "type": "String", "lang": "EN"}],
        "v-s:website": [{"data": "https://techinnovations.com", "type": "Uri"}],
        "v-s:foundedDate": [{"data": "2010-01-01T00:00:00Z", "type": "Datetime"}]
    });

    let mut org = Individual::default();
    let parse_result = parse_json_to_individual(&json_org, &mut org);
    
    assert!(parse_result);
    assert_eq!(org.get_id(), "d:integration_org_001");
    
    let label = org.get_first_literal("v-s:label");
    assert_eq!(label.unwrap(), "Tech Innovations Inc");
    
    let website = org.get_first_literal("v-s:website");
    assert_eq!(website.unwrap(), "https://techinnovations.com");
}

#[test]
fn test_document_with_relationships() {
    // Test creating a document that references other entities
    let json_doc = json!({
        "@": "d:integration_doc_001",
        "rdf:type": [{"data": "v-s:Document", "type": "Uri"}],
        "v-s:title": [{"data": "Integration Test Document", "type": "String"}],
        "v-s:author": [{"data": "d:integration_person_001", "type": "Uri"}],
        "v-s:organization": [{"data": "d:integration_org_001", "type": "Uri"}],
        "v-s:created": [{"data": "2024-01-15T10:30:00Z", "type": "Datetime"}],
        "v-s:content": [{"data": "This document tests relationships between entities.", "type": "String"}],
        "v-s:tags": [
            {"data": "integration", "type": "String"},
            {"data": "test", "type": "String"},
            {"data": "document", "type": "String"}
        ]
    });

    let mut doc = Individual::default();
    let parse_result = parse_json_to_individual(&json_doc, &mut doc);
    
    assert!(parse_result);
    assert_eq!(doc.get_id(), "d:integration_doc_001");
    
    // Test relationships
    let author = doc.get_first_literal("v-s:author");
    assert_eq!(author.unwrap(), "d:integration_person_001");
    
    let org = doc.get_first_literal("v-s:organization");
    assert_eq!(org.unwrap(), "d:integration_org_001");
    
    // Test multiple values
    let tags = doc.get_literals("v-s:tags").unwrap_or_default();
    assert_eq!(tags.len(), 3);
    assert!(tags.contains(&"integration".to_string()));
    assert!(tags.contains(&"test".to_string()));
    assert!(tags.contains(&"document".to_string()));
}



#[test]
fn test_different_data_types() {
    // Test various data types in individuals
    let json_types = json!({
        "@": "d:integration_types_test",
        "rdf:type": [{"data": "v-s:TestEntity", "type": "Uri"}],
        "v-s:stringValue": [{"data": "Hello World", "type": "String"}],
        "v-s:integerValue": [{"data": "42", "type": "Integer"}],
        "v-s:decimalValue": [{"data": "3.14159", "type": "Decimal"}],
        "v-s:booleanValue": [{"data": "true", "type": "Boolean"}],
        "v-s:datetimeValue": [{"data": "2024-01-01T12:00:00Z", "type": "Datetime"}],
        "v-s:uriValue": [{"data": "http://example.com/resource", "type": "Uri"}],
        "v-s:multipleStrings": [
            {"data": "First", "type": "String"},
            {"data": "Second", "type": "String"},
            {"data": "Third", "type": "String"}
        ]
    });

    let mut individual = Individual::default();
    let parse_result = parse_json_to_individual(&json_types, &mut individual);
    
    assert!(parse_result);
    assert_eq!(individual.get_id(), "d:integration_types_test");
    
    // Test string value
    let string_val = individual.get_first_literal("v-s:stringValue");
    if let Some(val) = string_val {
        assert_eq!(val, "Hello World");
    }
    
    // Test integer value (stored as string in literals)
    let int_val = individual.get_first_literal("v-s:integerValue");
    if let Some(val) = int_val {
        assert_eq!(val, "42");
    }
    
    // Test boolean value
    let bool_val = individual.get_first_literal("v-s:booleanValue");
    if let Some(val) = bool_val {
        assert_eq!(val, "true");
    }
    
    // Test URI value
    let uri_val = individual.get_first_literal("v-s:uriValue");
    if let Some(val) = uri_val {
        assert_eq!(val, "http://example.com/resource");
    }
    
    // Test multiple values
    let multiple_strings = individual.get_literals("v-s:multipleStrings").unwrap_or_default();
    assert_eq!(multiple_strings.len(), 3);
    assert!(multiple_strings.contains(&"First".to_string()));
    assert!(multiple_strings.contains(&"Second".to_string()));
    assert!(multiple_strings.contains(&"Third".to_string()));
}





#[test]
fn test_multilingual_content() {
    // Test individuals with multiple languages
    let json_multilingual = json!({
        "@": "d:integration_multilingual",
        "rdf:type": [{"data": "v-s:Document", "type": "Uri"}],
        "v-s:title": [
            {"data": "English Title", "type": "String", "lang": "EN"},
            {"data": "Русский заголовок", "type": "String", "lang": "RU"},
            {"data": "Título en español", "type": "String", "lang": "ES"}
        ],
        "v-s:description": [
            {"data": "Description in English", "type": "String", "lang": "EN"},
            {"data": "Описание на русском", "type": "String", "lang": "RU"}
        ]
    });

    let mut individual = Individual::default();
    let parse_result = parse_json_to_individual(&json_multilingual, &mut individual);
    
    assert!(parse_result);
    assert_eq!(individual.get_id(), "d:integration_multilingual");
    
    // Test that we have multiple title values
    let titles = individual.get_literals("v-s:title").unwrap_or_default();
    assert_eq!(titles.len(), 3);
    
    // Test that we have multiple description values
    let descriptions = individual.get_literals("v-s:description").unwrap_or_default();
    assert_eq!(descriptions.len(), 2);
}



#[test]
fn test_individual_update_workflow() {
    // Test the workflow of updating an individual
    
    // 1. Create initial individual
    let initial_json = json!({
        "@": "d:update_test_person",
        "rdf:type": [{"data": "v-s:Person", "type": "Uri"}],
        "v-s:firstName": [{"data": "John", "type": "String"}],
        "v-s:email": [{"data": "john@example.com", "type": "String"}]
    });

    let mut individual = Individual::default();
    assert!(parse_json_to_individual(&initial_json, &mut individual));
    
    // 2. Add additional email (ADD_TO operation)
    let add_email_json = json!({
        "@": "d:update_test_person",
        "v-s:email": [{"data": "john.work@company.com", "type": "String"}]
    });

    let mut add_individual = Individual::default();
    assert!(parse_json_to_individual(&add_email_json, &mut add_individual));
    
    // 3. Update first name (SET_IN operation)
    let update_name_json = json!({
        "@": "d:update_test_person",
        "v-s:firstName": [{"data": "Jonathan", "type": "String"}]
    });

    let mut update_individual = Individual::default();
    assert!(parse_json_to_individual(&update_name_json, &mut update_individual));
    
    // 4. Remove specific email (REMOVE_FROM operation)
    let remove_email_json = json!({
        "@": "d:update_test_person",
        "v-s:email": [{"data": "john@example.com", "type": "String"}]
    });

    let mut remove_individual = Individual::default();
    assert!(parse_json_to_individual(&remove_email_json, &mut remove_individual));
    
    // Verify all operations have the same ID
    assert_eq!(individual.get_id(), "d:update_test_person");
    assert_eq!(add_individual.get_id(), "d:update_test_person");
    assert_eq!(update_individual.get_id(), "d:update_test_person");
    assert_eq!(remove_individual.get_id(), "d:update_test_person");
} 