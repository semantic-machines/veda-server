# Indexing Logic Documentation

## Overview

The `veda-az-indexer` processes authorization data and maintains indexes for efficient access control checks. The indexer handles four main types of objects:
- Permission Statements
- Memberships
- Permission Filters
- Accounts

## Core Concepts

### Index Format

The indexer supports two index format versions (v1 and v2), configurable via `--use_index_format_v1` flag.

### Access Rights

Access rights are represented as bit flags:
- `CanCreate` - Permission to create objects
- `CanRead` - Permission to read objects
- `CanUpdate` - Permission to update objects
- `CanDelete` - Permission to delete objects

Each permission can also have negative counterparts (`CantCreate`, `CantRead`, etc.) to explicitly deny access.

### Index Keys

The indexer uses prefixed keys to store different types of data:
- `P` - Permission statements (PERMISSION_PREFIX)
- `M` - Memberships (MEMBERSHIP_PREFIX)
- `F` - Permission filters (FILTER_PREFIX)
- `_L:` - Account login mappings

### ACLRecord Structure

Each authorization record (ACLRecord) contains the following fields:
- `id` (String) - Identifier of the subject (user/group)
- `access` (u8) - Bit mask of access rights
- `marker` (char) - Special markers (0, M_IS_EXCLUSIVE, M_IGNORE_EXCLUSIVE)
- `is_deleted` (bool) - Flag indicating if the record is deleted
- `level` (u8) - Hierarchy level (currently always 0)
- `counters` (HashMap) - Counter map for tracking incremental permission changes

## Indexing Process

### 1. Permission Statement Indexing

Permission statements define what subjects (users/groups) can do with what objects (resources).

#### Data Structure

A permission statement contains:
- `v-s:permissionObject` - The resource(s) being protected (can be single value or array)
- `v-s:permissionSubject` - Who gets the permission - user(s) or group(s) (can be single value or array)
- `v-s:canCreate`, `v-s:canRead`, `v-s:canUpdate`, `v-s:canDelete` - Access rights (boolean)

#### Example 1: Creating a New Permission

**Input Individual:**
```
{
  "@id": "d:permission_1",
  "rdf:type": "v-s:PermissionStatement",
  "v-s:permissionObject": "d:document_123",
  "v-s:permissionSubject": "d:user_alice",
  "v-s:canRead": true,
  "v-s:canUpdate": true
}
```

**Processing Steps:**
1. Extract resource: `d:document_123`
2. Extract subject: `d:user_alice`
3. Calculate access mask: `CanRead | CanUpdate` = 0x06
4. Generate index key: `P` + `d:document_123` = `Pd:document_123`
5. Create/update ACLRecord with subject `d:user_alice` and access `0x06`
6. Encode and store to LMDB

**Storage Result:**
```
Key: "Pd:document_123"
Value: Encoded ACLRecordSet containing:
  - Record: { 
      id: "d:user_alice", 
      access: 0x06, 
      marker: 0, 
      is_deleted: false,
      level: 0,
      counters: {}
    }
```

#### Example 2: Updating a Permission

**Previous State:**
```
{
  "@id": "d:permission_1",
  "v-s:permissionObject": "d:document_123",
  "v-s:permissionSubject": "d:user_alice",
  "v-s:canRead": true
}
```

**New State:**
```
{
  "@id": "d:permission_1",
  "v-s:permissionObject": "d:document_123",
  "v-s:permissionSubject": "d:user_alice",
  "v-s:canRead": true,
  "v-s:canUpdate": true,
  "v-s:canDelete": true
}
```

**Processing Steps:**
1. Previous access: `CanRead` = 0x02
2. New access: `CanRead | CanUpdate | CanDelete` = 0x0E
3. Load existing ACLRecordSet for `Pd:document_123`
4. Update counters to reflect change from 0x02 to 0x0E
5. Store updated record

**Storage Result:**
```
Key: "Pd:document_123"
Value: Updated ACLRecordSet with access 0x0E for d:user_alice
```

#### Example 3: Deleting a Permission

**Processing:**
When `v-s:deleted: true` is set, the indexer:
1. Marks the record as `is_deleted: true`
2. Updates counters to remove the permission bits
3. If all permissions are removed, the record remains but is marked deleted

### 2. Membership Indexing

Memberships define group membership relationships (user belongs to group).

#### Data Structure

A membership contains:
- `v-s:resource` - The user(s)/entity(ies) (can be single value or array)
- `v-s:memberOf` - The group(s) they belong to (can be single value or array)

#### Example 1: Adding User to Group

**Input Individual:**
```
{
  "@id": "d:membership_1",
  "rdf:type": "v-s:Membership",
  "v-s:resource": "d:user_bob",
  "v-s:memberOf": "d:group_admins"
}
```

**Processing Steps:**
1. Extract resource: `d:user_bob`
2. Extract groups: `d:group_admins`
3. Default access: `CanCreate | CanRead | CanUpdate | CanDelete` = 0x0F
4. Generate index key: `M` + `d:user_bob` = `Md:user_bob`
5. Create ACLRecord with `d:group_admins` and access 0x0F

**Storage Result:**
```
Key: "Md:user_bob"
Value: Encoded ACLRecordSet containing:
  - Record: { 
      id: "d:group_admins", 
      access: 0x0F, 
      marker: 0, 
      is_deleted: false,
      level: 0,
      counters: {}
    }
```

#### Example 2: Multiple Group Membership

**Input Individual:**
```
{
  "@id": "d:membership_2",
  "rdf:type": "v-s:Membership",
  "v-s:resource": "d:user_charlie",
  "v-s:memberOf": ["d:group_users", "d:group_developers"]
}
```

**Storage Result:**
```
Key: "Md:user_charlie"
Value: Encoded ACLRecordSet containing:
  - Record: { 
      id: "d:group_users", 
      access: 0x0F, 
      marker: 0, 
      is_deleted: false,
      level: 0,
      counters: {}
    }
  - Record: { 
      id: "d:group_developers", 
      access: 0x0F, 
      marker: 0, 
      is_deleted: false,
      level: 0,
      counters: {}
    }
```

### 3. Permission Filter Indexing

Permission filters allow complex authorization scenarios with filtering.

#### Data Structure

A permission filter contains:
- `v-s:permissionObject` - The resource(s) that will be indexed (can be single value or array)
- `v-s:resource` - The subject(s) that will have access via filter (can be single value or array)
- `v-s:useFilter` - Filter expression string (optional, single value)

#### Example: Filter with Expression

**Input Individual:**
```
{
  "@id": "d:filter_1",
  "rdf:type": "v-s:PermissionFilter",
  "v-s:permissionObject": "d:department_123",
  "v-s:resource": "d:group_managers",
  "v-s:useFilter": "expression_abc"
}
```

**Processing Steps:**
1. Extract resources for indexing: `d:department_123`
2. Extract subjects: `d:group_managers`
3. Extract filter: `expression_abc`
4. Generate index key: `F` + `expression_abc` + `d:department_123`

**Storage Result:**
```
Key: "Fexpression_abcd:department_123"
Value: Encoded ACLRecordSet containing record for d:group_managers
```

### 4. Account Indexing

Account indexing creates a mapping from login to account ID for fast lookups.

#### Example 1: New Account

**Input Individual:**
```
{
  "@id": "d:account_alice",
  "rdf:type": "v-s:Account",
  "v-s:login": "alice@example.com"
}
```

**Processing Steps:**
1. Extract login: `alice@example.com`
2. Convert to lowercase: `alice@example.com`
3. Generate key: `_L:alice@example.com`
4. Store account ID

**Storage Result:**
```
Key: "_L:alice@example.com"
Value: "d:account_alice"
```

#### Example 2: Deleting Account

**Processing:**
When account is deleted (empty new_state):
1. Extract login from previous state
2. Generate key: `_L:{login}`
3. Remove key from storage

## Advanced Features

### Exclusive and Ignore Exclusive Markers

Permissions can be marked with special markers:
- `v-s:isExclusive: true` - This permission is exclusive (M_IS_EXCLUSIVE marker)
- `v-s:ignoreExclusive: true` - This permission ignores exclusive checks (M_IGNORE_EXCLUSIVE marker)

#### Example: Exclusive Permission

**Input Individual:**
```
{
  "@id": "d:permission_2",
  "rdf:type": "v-s:PermissionStatement",
  "v-s:permissionObject": "d:document_456",
  "v-s:permissionSubject": "d:user_david",
  "v-s:canRead": true,
  "v-s:isExclusive": true
}
```

The resulting ACLRecord will have `marker: M_IS_EXCLUSIVE`.

### Drop Count Feature

The `v-s:dropCount` flag enables special counter handling for incremental updates.

#### Example: Drop Count Permission

**Input Individual:**
```
{
  "@id": "d:permission_3",
  "rdf:type": "v-s:PermissionStatement",
  "v-s:permissionObject": "d:document_789",
  "v-s:permissionSubject": "d:user_eve",
  "v-s:canRead": true,
  "v-s:dropCount": true,
  "v-s:updateCounter": 1
}
```

**Processing:**
When `dropCount` is true and `updateCounter > 1`, the indexer skips processing to avoid conflicts.

### Disappeared Resources Handling

When updating a permission/membership, the indexer detects resources that were removed.

#### Example: Resource Removal

**Previous State:**
```
{
  "v-s:permissionObject": ["d:doc_1", "d:doc_2", "d:doc_3"]
}
```

**New State:**
```
{
  "v-s:permissionObject": ["d:doc_1", "d:doc_3"]
}
```

**Processing:**
1. Detect disappeared: `d:doc_2`
2. Generate deletion update for `Pd:doc_2`
3. Mark the permission record as deleted in that index

## ACL Cache

The indexer maintains an optional cache for frequently accessed authorization data.

### Cache Workflow

1. **Initial Storage**: Authorization records are stored in main LMDB database
2. **Usage Tracking**: Statistics files track access frequency for each identifier
3. **Cache Population**: Records exceeding threshold are copied to cache with timestamp
4. **Cache Expiration**: Daily cleanup removes expired entries based on timestamp
5. **Cache Update**: When permission changes, both main storage and cache are updated

#### Example: Cache Entry

**Storage Format:**
```
Key: "Pd:document_popular"
Value: <timestamp><encoded_record_set>
  - Timestamp: 2024-10-27T10:30:00Z
  - ACLRecordSet: { "d:user_alice": { access: 0x06, ... } }
```

### Statistics Processing

Statistics files (`.processed` extension) contain usage data:

**File Format:**
```
2024-10-27T10:00:00Z;Pd:document_123,150;Pd:document_456,200
```

- Timestamp of measurement
- Identifier and access count (separated by comma)
- Multiple identifiers separated by semicolon

**Processing Steps:**
1. Read `.processed` files from `./data/stat/`
2. Parse identifier and count
3. If count >= `min_identifier_count_threshold`
4. Check if already in cache
5. If not, load from main storage and add to cache with current timestamp
6. Rename file to `.ok` when complete

## Multi-Resource Indexing

Permissions can target multiple resources simultaneously.

#### Example: Multiple Resources

**Input Individual:**
```
{
  "@id": "d:permission_4",
  "rdf:type": "v-s:PermissionStatement",
  "v-s:permissionObject": ["d:doc_1", "d:doc_2", "d:doc_3"],
  "v-s:permissionSubject": "d:user_frank",
  "v-s:canRead": true
}
```

**Storage Result:**
Three separate index entries:
```
Key: "Pd:doc_1" -> ACLRecordSet with d:user_frank
Key: "Pd:doc_2" -> ACLRecordSet with d:user_frank  
Key: "Pd:doc_3" -> ACLRecordSet with d:user_frank
```

## Counter Management

The indexer maintains internal counters for each permission bit to handle incremental updates correctly. This allows multiple permission statements to grant the same access right to the same subject on the same resource.

### Counter Structure

Each ACLRecord contains a `counters` HashMap (char -> u16) that tracks count for each access right:
- Positive permissions: 'c' (CanCreate), 'r' (CanRead), 'u' (CanUpdate), 'd' (CanDelete)
- Negative permissions: '!' (CantCreate), '~' (CantRead), '-' (CantUpdate), '*' (CantDelete)

### Counter Update Logic

The `update_counters` function processes counters based on several factors:
- `prev_access`: Access bits from the previous version
- `cur_access`: Access bits from the current version  
- `is_deleted`: Whether the record is being deleted
- `is_drop_count`: Special mode flag (from `v-s:dropCount` field)

#### Normal Mode (is_drop_count = false)

**When counter exists for an access bit:**

1. **If current access contains this bit:**
   - **Not deleted**: counter += 1, bit is set
   - **Deleted and previous had bit**: counter -= 1, bit removed if counter == 0

2. **If current access doesn't contain this bit:** No changes

**When counter doesn't exist:**
- If not deleted and current access contains bit: create counter = 1

#### Drop Count Mode (is_drop_count = true)

This mode is used when `v-s:dropCount: true` is set. It provides different semantics:

**When counter exists for an access bit:**

1. **If current access contains this bit:**
   - **Not deleted**: counter = 1 (reset to 1, not incremented!)
   - **Deleted**: counter = 0, bit removed

2. **If current access doesn't contain this bit:**
   - **If counter > 0**: bit is ADDED to access! (counter restores the permission)

**When counter doesn't exist:**
- Same as normal mode: if not deleted and current access contains bit, create counter = 1

#### Example: Counter Evolution (Normal Mode)

**Step 1: First Permission Grants Access**
```
Individual d:perm_1 grants CanRead (0x02) to d:user_alice on d:doc_123
Counters: { 'r': 1 }
Resulting access: 0x02 (CanRead)
```

**Step 2: Second Permission Grants Same Access**
```
Individual d:perm_2 also grants CanRead (0x02) to d:user_alice on d:doc_123
Counters: { 'r': 2 }
Resulting access: 0x02 (CanRead, still present)
```

**Step 3: First Permission Deleted**
```
Individual d:perm_1 is deleted
prev_access: 0x02, is_deleted: true
Counters: { 'r': 1 } (decremented from 2 to 1)
Resulting access: 0x02 (CanRead still present because counter > 0!)
```

**Step 4: Second Permission Deleted**
```
Individual d:perm_2 is deleted  
prev_access: 0x02, is_deleted: true
Counters: { 'r': 0 } (decremented from 1 to 0)
Resulting access: 0x00 (CanRead removed because counter == 0)
Record marked as is_deleted: true
```

#### Example: Counter Evolution (Drop Count Mode)

**Step 1: Permission with dropCount**
```
Individual d:perm_3 with v-s:dropCount: true grants CanRead (0x02)
Counters: { 'r': 1 }
Resulting access: 0x02 (CanRead)
```

**Step 2: Update Permission (remove CanRead)**
```
Individual d:perm_3 updated to remove v-s:canRead
cur_access: 0x00 (no CanRead bit)
Counter exists: { 'r': 1 } from previous
Current access doesn't have CanRead bit, BUT counter > 0
Resulting access: 0x02 (CanRead RESTORED by counter!)
```

**Step 3: Delete Permission**
```
Individual d:perm_3 deleted with is_deleted: true
Counters: { 'r': 0 }
Resulting access: 0x00 (CanRead finally removed)
```

### Storage Examples with Filled Counters

Here are complete examples showing what ACLRecord structures look like when counters are active:

#### Example 1: Multiple Permissions on Same Resource

**Scenario:** Two different permissions grant CanRead to the same user on the same document.

**First Permission Created:**
```
{
  "@id": "d:permission_A",
  "v-s:permissionObject": "d:document_999",
  "v-s:permissionSubject": "d:user_john",
  "v-s:canRead": true
}
```

**Storage after first permission:**
```
Key: "Pd:document_999"
Value: Encoded ACLRecordSet containing:
  - Record: {
      id: "d:user_john",
      access: 0x02,
      marker: 0,
      is_deleted: false,
      level: 0,
      counters: {}
    }
```

**Second Permission Created:**
```
{
  "@id": "d:permission_B",
  "v-s:permissionObject": "d:document_999",
  "v-s:permissionSubject": "d:user_john",
  "v-s:canRead": true,
  "v-s:canUpdate": true
}
```

**Storage after second permission (counters now active!):**
```
Key: "Pd:document_999"
Value: Encoded ACLRecordSet containing:
  - Record: {
      id: "d:user_john",
      access: 0x06,
      marker: 0,
      is_deleted: false,
      level: 0,
      counters: { 'r': 2, 'u': 1 }
    }
```
Note: 'r' counter = 2 (both permissions grant CanRead), 'u' counter = 1 (only second grants CanUpdate)

**After deleting permission_A:**
```
Key: "Pd:document_999"
Value: Encoded ACLRecordSet containing:
  - Record: {
      id: "d:user_john",
      access: 0x06,
      marker: 0,
      is_deleted: false,
      level: 0,
      counters: { 'r': 1, 'u': 1 }
    }
```
Note: CanRead (0x02) bit still present because 'r' counter = 1 (permission_B still grants it)

#### Example 2: Membership with Multiple Sources

**Scenario:** Two membership records add the same user to the same group.

**First Membership:**
```
{
  "@id": "d:membership_X",
  "v-s:resource": "d:user_sara",
  "v-s:memberOf": "d:group_editors"
}
```

**Storage after first membership:**
```
Key: "Md:user_sara"
Value: Encoded ACLRecordSet containing:
  - Record: {
      id: "d:group_editors",
      access: 0x0F,
      marker: 0,
      is_deleted: false,
      level: 0,
      counters: {}
    }
```

**Second Membership (same user to same group from different source):**
```
{
  "@id": "d:membership_Y",
  "v-s:resource": "d:user_sara",
  "v-s:memberOf": "d:group_editors"
}
```

**Storage after second membership (counters filled!):**
```
Key: "Md:user_sara"
Value: Encoded ACLRecordSet containing:
  - Record: {
      id: "d:group_editors",
      access: 0x0F,
      marker: 0,
      is_deleted: false,
      level: 0,
      counters: { 'c': 2, 'r': 2, 'u': 2, 'd': 2 }
    }
```
Note: All four permission bits have counter = 2 (both memberships grant full access 0x0F)

#### Example 3: Mixed Permissions

**Storage with different permission combinations:**
```
Key: "Pd:project_alpha"
Value: Encoded ACLRecordSet containing:
  - Record: {
      id: "d:user_tom",
      access: 0x0E,
      marker: 0,
      is_deleted: false,
      level: 0,
      counters: { 'r': 3, 'u': 2, 'd': 1 }
    }
  - Record: {
      id: "d:group_admins",
      access: 0x0F,
      marker: 0,
      is_deleted: false,
      level: 0,
      counters: { 'c': 1, 'r': 1, 'u': 1, 'd': 1 }
    }
```
Note: 
- user_tom has 3 sources granting CanRead, 2 granting CanUpdate, 1 granting CanDelete
- group_admins has 1 source granting all permissions

### Why Counters?

The counter mechanism ensures:
1. **Multiple grants are tracked**: When multiple permissions grant the same access right, all must be removed before access is revoked
2. **Incremental updates work correctly**: Adding/removing individual permissions doesn't affect other grants
3. **Drop count mode preserves access**: Useful for special scenarios where access should persist despite field changes
4. **Race condition handling**: Even if permission updates arrive out of order, counters help maintain consistency

## Error Handling

### Storage Errors

When a storage operation fails:
```rust
StorageError::StoragePutError {
    key: "Pd:document_123",
    source: "storage"
}
```

The error is logged and processing continues with the next item.

### Invalid Data

Invalid or malformed individuals are logged and skipped:
- Missing required fields
- Invalid type
- Conflicting flags (e.g., dropCount with updateCounter > 1)

## Performance Considerations

### Batch Processing

The indexer processes items in batches:
- After every 100 items, processing statistics are logged
- Heartbeat function runs cache cleanup and statistics processing
- Cleanup operations are time-limited to avoid blocking

### Index Key Design

Index keys are designed for fast lookups:
- Prefix-based organization (P, M, F, _L)
- Direct resource ID mapping
- Filter expressions embedded in keys

### Cache Strategy

The cache improves performance for frequently accessed items:
- Usage threshold prevents cache pollution
- Expiration removes stale entries
- Incremental cleanup avoids long pauses
- Time-limited operations prevent blocking

## Queue Processing

### Message Format

Queue messages contain:
- `cmd`: Operation type (Create, Update, Remove)
- `op_id`: Operation identifier
- `prev_state`: Previous object state (binary)
- `new_state`: New object state (binary)

### Processing Flow

1. Read message from `individuals-flow` queue
2. Decode `prev_state` and `new_state`
3. Check `rdf:type` to determine handler
4. Call appropriate indexing function
5. Update module_info with op_id
6. Acknowledge message

## System Account Bootstrap

On first run, the indexer creates a default system permission:

```
{
  "@id": "cfg:VedaSystemPermission",
  "rdf:type": "v-s:PermissionStatement",
  "v-s:permissionSubject": "cfg:VedaSystem",
  "v-s:permissionObject": "v-s:AllResourcesGroup",
  "v-s:canCreate": true
}
```

This ensures the system account has necessary permissions to operate.

