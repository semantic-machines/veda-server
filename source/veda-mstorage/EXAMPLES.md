# Veda MStorage Examples

This document provides practical examples of using the Veda MStorage API.

## Basic Setup

Before using the API, ensure the service is running and you have:
- A valid authentication ticket
- Proper network configuration
- Required permissions for operations

## Request Format

All requests use JSON format over nanomsg protocol:

```json
{
  "ticket": "your_auth_ticket",
  "function": "operation_name",
  "individuals": [/* individual objects */],
  "event_id": "optional_event_id",
  "src": "client_identifier",
  "assigned_subsystems": 1
}
```

### Request Parameters

- `ticket` - Authentication ticket (required)
- `function` - Operation type: put, remove, add_to, set_in, remove_from, remove_predicates (required)
- `individuals` - Array of semantic entities to process (required)
- `event_id` - Optional identifier for tracking related operations
- `src` - Source identifier for operation logging
- `assigned_subsystems` - Bitmask for subsystem notifications (1 = notify all)

## Response Format

Successful responses:
```json
{
  "type": "OpResult",
  "data": [
    {
      "result": 200,
      "op_id": 12345
    }
  ]
}
```

Error responses:
```json
{
  "type": "OpResult",
  "result": 472
}
```

Note: Error codes are numeric values representing specific error conditions.

## Operation Examples

### 1. Creating a New Individual (PUT)

Create a person record:

```json
{
  "ticket": "admin_ticket_123",
  "function": "put",
  "individuals": [
    {
      "@": "d:person_001",
      "rdf:type": [
        {"data": "v-s:Person", "type": "Uri"}
      ],
      "v-s:firstName": [
        {"data": "John", "type": "String", "lang": "EN"}
      ],
      "v-s:lastName": [
        {"data": "Doe", "type": "String", "lang": "EN"}
      ],
      "v-s:email": [
        {"data": "john.doe@example.com", "type": "String"}
      ],
      "v-s:birthDate": [
        {"data": "1990-01-15T00:00:00Z", "type": "Datetime"}
      ]
    }
  ],
  "src": "user_interface",
  "event_id": "create_person_001",
  "assigned_subsystems": 1
}
```

### 2. Creating an Organization (PUT)

```json
{
  "ticket": "admin_ticket_123",
  "function": "put",
  "individuals": [
    {
      "@": "d:org_001",
      "rdf:type": [
        {"data": "v-s:Organization", "type": "Uri"}
      ],
      "v-s:label": [
        {"data": "Acme Corporation", "type": "String", "lang": "EN"}
      ],
      "v-s:description": [
        {"data": "Technology company", "type": "String", "lang": "EN"}
      ],
      "v-s:website": [
        {"data": "https://acme.com", "type": "Uri"}
      ]
    }
  ],
  "src": "admin_panel"
}
```

### 3. Adding Values to Existing Properties (ADD_TO)

Add a second email to the person:

```json
{
  "ticket": "user_ticket_456",
  "function": "add_to",
  "individuals": [
    {
      "@": "d:person_001",
      "v-s:email": [
        {"data": "john.work@acme.com", "type": "String"}
      ]
    }
  ],
  "src": "profile_update"
}
```

### 4. Setting Specific Values (SET_IN)

Update the person's first name:

```json
{
  "ticket": "user_ticket_456",
  "function": "set_in",
  "individuals": [
    {
      "@": "d:person_001",
      "v-s:firstName": [
        {"data": "Jonathan", "type": "String", "lang": "EN"}
      ]
    }
  ],
  "src": "profile_update"
}
```

### 5. Removing Specific Values (REMOVE_FROM)

Remove one email address:

```json
{
  "ticket": "user_ticket_456",
  "function": "remove_from",
  "individuals": [
    {
      "@": "d:person_001",
      "v-s:email": [
        {"data": "john.doe@example.com", "type": "String"}
      ]
    }
  ],
  "src": "profile_cleanup"
}
```

### 6. Removing Entire Properties (REMOVE_PREDICATES)

Remove the birth date property:

```json
{
  "ticket": "admin_ticket_123",
  "function": "remove_predicates",
  "individuals": [
    {
      "@": "d:person_001",
      "v-s:birthDate": []
    }
  ],
  "src": "privacy_compliance"
}
```

### 7. Deleting an Individual (REMOVE)

Delete the entire person record:

```json
{
  "ticket": "admin_ticket_123",
  "function": "remove",
  "individuals": [
    {
      "@": "d:person_001"
    }
  ],
  "src": "data_cleanup",
  "event_id": "delete_person_001"
}
```

## Complex Examples

### Batch Operations

Update multiple individuals in one transaction:

```json
{
  "ticket": "admin_ticket_123",
  "function": "put",
  "individuals": [
    {
      "@": "d:person_001",
      "v-s:position": [
        {"data": "Software Engineer", "type": "String"}
      ],
      "v-s:worksFor": [
        {"data": "d:org_001", "type": "Uri"}
      ]
    },
    {
      "@": "d:person_002",
      "rdf:type": [
        {"data": "v-s:Person", "type": "Uri"}
      ],
      "v-s:firstName": [
        {"data": "Jane", "type": "String"}
      ],
      "v-s:lastName": [
        {"data": "Smith", "type": "String"}
      ],
      "v-s:worksFor": [
        {"data": "d:org_001", "type": "Uri"}
      ]
    }
  ],
  "src": "hr_system",
  "assigned_subsystems": 1
}
```

### Document with Attachments

```json
{
  "ticket": "user_ticket_789",
  "function": "put",
  "individuals": [
    {
      "@": "d:document_001",
      "rdf:type": [
        {"data": "v-s:Document", "type": "Uri"}
      ],
      "v-s:title": [
        {"data": "Project Proposal", "type": "String"}
      ],
      "v-s:author": [
        {"data": "d:person_001", "type": "Uri"}
      ],
      "v-s:created": [
        {"data": "2024-01-15T10:30:00Z", "type": "Datetime"}
      ],
      "v-s:content": [
        {"data": "This is the content of the document...", "type": "String"}
      ],
      "v-s:hasAttachment": [
        {"data": "d:file_001", "type": "Uri"}
      ]
    }
  ],
  "src": "document_manager"
}
```

## Data Types

### Supported Value Types

- **String**: Text values with optional language
- **Uri**: Resource identifiers
- **Integer**: Numeric values
- **Decimal**: Floating-point numbers
- **Datetime**: ISO 8601 timestamps
- **Boolean**: true/false values
- **Binary**: Base64 encoded binary data

### Type Examples

```json
{
  "@": "d:example_001",
  "v-s:stringProperty": [
    {"data": "Hello World", "type": "String", "lang": "EN"}
  ],
  "v-s:uriProperty": [
    {"data": "http://example.com", "type": "Uri"}
  ],
  "v-s:integerProperty": [
    {"data": "42", "type": "Integer"}
  ],
  "v-s:decimalProperty": [
    {"data": "3.14159", "type": "Decimal"}
  ],
  "v-s:datetimeProperty": [
    {"data": "2024-01-15T10:30:00Z", "type": "Datetime"}
  ],
  "v-s:booleanProperty": [
    {"data": "true", "type": "Boolean"}
  ],
  "v-s:binaryProperty": [
    {"data": "SGVsbG8gV29ybGQ=", "type": "Binary"}  // Base64: "Hello World"
  ]
}
```

## Error Examples

### Invalid Ticket

Request:
```json
{
  "ticket": "invalid_ticket",
  "function": "put",
  "individuals": [{"@": "d:test"}]
}
```

Response:
```json
{
  "type": "OpResult",
  "result": 472  // TicketNotFound
}
```

### Insufficient Permissions

Request:
```json
{
  "ticket": "limited_user_ticket",
  "function": "remove",
  "individuals": [{"@": "d:admin_data"}]
}
```

Response:
```json
{
  "type": "OpResult",
  "result": 471  // NotAuthorized
}
```

### Invalid Individual ID

Request:
```json
{
  "ticket": "valid_ticket",
  "function": "put",
  "individuals": [{"@": ""}]
}
```

Response:
```json
{
  "type": "OpResult",
  "result": 422  // InvalidIdentifier
}
```

## Best Practices

### 1. Use Meaningful IDs
```json
// Good
{"@": "d:person_john_doe_001"}

// Avoid
{"@": "d:123456"}
```

### 2. Include Language Tags
```json
{
  "v-s:label": [
    {"data": "English Label", "type": "String", "lang": "EN"},
    {"data": "Русская метка", "type": "String", "lang": "RU"}
  ]
}
```

### 3. Use Proper Types
```json
{
  "v-s:created": [
    {"data": "2024-01-15T10:30:00Z", "type": "Datetime"}  // Not String
  ],
  "v-s:count": [
    {"data": "42", "type": "Integer"}  // Not String
  ]
}
```

### 4. Batch Related Operations
```json
// Create parent and children in one transaction
{
  "function": "put",
  "individuals": [
    {
      "@": "d:project_001",
      "rdf:type": [{"data": "v-s:Project", "type": "Uri"}]
    },
    {
      "@": "d:task_001",
      "rdf:type": [{"data": "v-s:Task", "type": "Uri"}],
      "v-s:hasProject": [{"data": "d:project_001", "type": "Uri"}]
    }
  ]
}
```

## Testing the API

### Using Test Framework

The project includes comprehensive tests that demonstrate API usage:

```bash
# Run integration tests to see API examples in action
cargo test --test integration_tests

# Run specific test patterns
cargo test test_individual_creation_workflow
cargo test test_batch_operations
cargo test test_authorization_scenarios
```

### Integration Test Examples

For more complex usage examples, see the integration tests in `tests/integration_tests.rs`:
- Multi-step workflows
- Error handling scenarios  
- Performance testing patterns
- Complex data type validation

### Protocol Notes

- **Transport**: nanomsg (nng) - not HTTP
- **Format**: Binary-wrapped JSON messages
- **Pattern**: Request-Reply for operations, Publish for notifications
- **Endpoints**: Configured via `veda.properties` file

For actual network testing, use a nanomsg-compatible client or the Veda platform tools.

## Advanced Features

### Subsystem Targeting

Control which subsystems receive notifications using `assigned_subsystems`:

```json
{
  "ticket": "admin_ticket_123",
  "function": "put", 
  "individuals": [
    {
      "@": "d:internal_data_001",
      "v-s:confidential": [{"data": "true", "type": "Boolean"}]
    }
  ],
  "assigned_subsystems": 2,  // Notify only specific subsystems
  "src": "secure_import"
}
```

### Event Tracking

Use `event_id` to group related operations:

```json
{
  "ticket": "user_ticket_456",
  "function": "put",
  "individuals": [/* batch of related changes */],
  "event_id": "user_profile_update_2024_01_15",
  "src": "profile_service"
}
```

## Common Patterns

### 1. User Profile Management
- Create user with PUT
- Update specific fields with SET_IN
- Add additional emails/phones with ADD_TO
- Remove outdated information with REMOVE_FROM

### 2. Document Workflow
- Create document with PUT
- Link to authors and reviewers
- Update status with SET_IN
- Add comments with ADD_TO

### 3. Organization Structure
- Create organization hierarchy
- Assign employees to departments
- Update reporting relationships
- Manage permissions and roles 