use crate::acl_cache::ACLCache;
use crate::tarantool_indexer::TarantoolIndexer;
use chrono::Utc;
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use v_common::v_authorization::record_formats::{decode_rec_to_rightset, encode_record, update_counters};
use v_common::module::info::ModuleInfo;
use v_individual_model::onto::individual::Individual;
use v_common::v_authorization::common::{Access, M_IGNORE_EXCLUSIVE, M_IS_EXCLUSIVE, PERMISSION_PREFIX};
use v_common::v_authorization::{ACLRecord, ACLRecordSet};
use log::{warn, debug};

// Trait for abstract storage operations
pub trait Storage {
    fn get(&mut self, key: &str) -> Option<String>;
    fn put(&mut self, key: &str, value: &str) -> bool;
    fn remove(&mut self, key: &str) -> bool;
}

// Определяем пользовательский тип ошибки
#[derive(Debug)]
pub enum StorageError {
    StoragePutError {
        key: String,
        source: String,
    },
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StorageError::StoragePutError {
                key,
                source,
            } => {
                write!(f, "Failed to put key '{key}' into {source}.")
            },
        }
    }
}

impl Error for StorageError {}

// Structure for storing access rights data
struct RightData<'a> {
    resource: &'a [String],
    in_set: &'a [String],
    access: u8,
}

// Structure for storing auxiliary data
struct AuxData<'a> {
    use_filter: &'a str,
    marker: char,
    is_drop_count: bool,
    prefix: &'a str,
}

// Structure for storing execution context
pub struct Context {
    pub permission_statement_counter: u32,
    pub membership_counter: u32,
    pub storage: Box<dyn Storage>,
    pub version_of_index_format: u8,
    pub module_info: ModuleInfo,
    pub acl_cache: Option<ACLCache>,
    pub tarantool_indexer: Option<TarantoolIndexer>,
}

// Function to get the access value from an individual object
pub fn get_access_from_individual(state: &mut Individual) -> u8 {
    let mut access = 0;

    if let Some(v) = state.get_first_bool("v-s:canCreate") {
        if v {
            access |= Access::CanCreate as u8;
        } else {
            access |= Access::CantCreate as u8;
        }
    }

    if let Some(v) = state.get_first_bool("v-s:canRead") {
        if v {
            access |= Access::CanRead as u8;
        } else {
            access |= Access::CantRead as u8;
        }
    }

    if let Some(v) = state.get_first_bool("v-s:canUpdate") {
        if v {
            access |= Access::CanUpdate as u8;
        } else {
            access |= Access::CantUpdate as u8;
        }
    }

    if let Some(v) = state.get_first_bool("v-s:canDelete") {
        if v {
            access |= Access::CanDelete as u8;
        } else {
            access |= Access::CantDelete as u8;
        }
    }

    access
}

// Function for indexing access right sets
// - Extracts information about resources, groups, and access rights from the previous and new object states.
// - Determines if the object is deleted, restored, or updated.
// - Calls the add_or_del_right_sets() function to add or remove access right sets.

pub fn index_right_sets(
    prev_state: &mut Individual,
    new_state: &mut Individual,
    prd_rsc: &str,
    prd_in_set: &str,
    prefix: &str,
    default_access: u8,
    ctx: &mut Context,
) -> Result<(), StorageError> {
    let mut is_drop_count = false;

    if let Some(b) = new_state.get_first_bool("v-s:dropCount") {
        if new_state.get_first_integer("v-s:updateCounter").unwrap_or(0) > 1 {
            warn!("detected v-s:updateCounter > 1 with v-s:dropCount, skip indexing {}", new_state.get_id());
            return Ok(());
        }

        is_drop_count = b;
    }

    let n_is_del = new_state.get_first_bool("v-s:deleted").unwrap_or_default();
    let p_is_del = prev_state.get_first_bool("v-s:deleted").unwrap_or_default();

    let mut n_acs = get_access_from_individual(new_state);
    let mut p_acs = get_access_from_individual(prev_state);

    if n_acs == 0 {
        n_acs = default_access;
    }

    if p_acs == 0 {
        p_acs = default_access;
    }

    let pre_resc = prev_state.get_literals(prd_rsc).unwrap_or_default();
    let pre_in_set = prev_state.get_literals(prd_in_set).unwrap_or_default();

    let use_filter = new_state.get_first_literal("v-s:useFilter").unwrap_or_default();

    let resc = new_state.get_literals(prd_rsc).unwrap_or_default();
    let in_set = new_state.get_literals(prd_in_set).unwrap_or_default();

    let ignr_excl = new_state.get_first_bool("v-s:ignoreExclusive").unwrap_or_default();
    let is_excl = new_state.get_first_bool("v-s:isExclusive").unwrap_or_default();

    let marker = if is_excl {
        M_IS_EXCLUSIVE
    } else if ignr_excl {
        M_IGNORE_EXCLUSIVE
    } else {
        0 as char
    };

    let id = new_state.get_id();

    let new_data = RightData {
        resource: &resc,
        in_set: &in_set,
        access: n_acs,
    };

    let prev_data = RightData {
        resource: &pre_resc,
        in_set: &pre_in_set,
        access: p_acs,
    };

    let aux_data = AuxData {
        use_filter: &use_filter,
        marker,
        is_drop_count,
        prefix,
    };

    if n_is_del && !p_is_del {
        // Object is deleted
        let mut cache = HashMap::new();
        let mut cache_ctx = CacheContext {
            cache: &mut cache,
            mode: &CacheType::None,
        };
        add_or_del_right_sets(id, &new_data, &prev_data, &aux_data, n_is_del, ctx, &mut cache_ctx)?;
    } else if !n_is_del && p_is_del {
        // Object is restored
        let mut cache = HashMap::new();
        let mut cache_ctx = CacheContext {
            cache: &mut cache,
            mode: &CacheType::Read,
        };
        add_or_del_right_sets(id, &new_data, &prev_data, &aux_data, false, ctx, &mut cache_ctx)?;
    } else if !n_is_del && !p_is_del {
        // Object is updated
        let mut cache = HashMap::new();
        let mut cache_ctx = CacheContext {
            cache: &mut cache,
            mode: &CacheType::Read,
        };
        if !pre_resc.is_empty() {
            let empty_data = RightData {
                resource: &[],
                in_set: &[],
                access: p_acs,
            };

            // Temporarily change cache mode to None for deletion
            cache_ctx.mode = &CacheType::None;
            add_or_del_right_sets(id, &prev_data, &empty_data, &aux_data, true, ctx, &mut cache_ctx)?;
            // Restore cache mode to Read
            cache_ctx.mode = &CacheType::Read;
        }

        add_or_del_right_sets(id, &new_data, &prev_data, &aux_data, false, ctx, &mut cache_ctx)?;
    }

    Ok(())
}

// Enumeration for caching mode
#[derive(PartialEq, Debug)]
enum CacheType {
    Write,
    Read,
    None,
}

// Structure for caching context
struct CacheContext<'a> {
    cache: &'a mut HashMap<String, String>,
    mode: &'a CacheType,
}

// Structure for processing context
struct ProcessingContext {
    is_deleted: bool,
    prev_access: u8,
}

// Function for adding or removing access right sets
fn add_or_del_right_sets(
    id: &str,
    new_data: &RightData,
    prev_data: &RightData,
    aux_data: &AuxData,
    is_deleted: bool,
    ctx: &mut Context,
    cache_ctx: &mut CacheContext,
) -> Result<(), StorageError> {
    // Get the resources and groups that have been removed
    let removed_resource = get_disappeared(prev_data.resource, new_data.resource);
    let removed_in_set = get_disappeared(prev_data.in_set, new_data.in_set);

    if is_deleted && new_data.resource.is_empty() && new_data.in_set.is_empty() {
        // If the object is deleted and there are no new resources or groups,
        // use the previous data for updating the access right set
        let t_data = RightData {
            resource: prev_data.resource,
            in_set: prev_data.in_set,
            access: new_data.access,
        };

        let proc_ctx = ProcessingContext {
            is_deleted,
            prev_access: prev_data.access,
        };
        update_right_set(id, &t_data, proc_ctx, aux_data, ctx, cache_ctx)?;
    } else {
        // Update the access right set with the new data
        let proc_ctx = ProcessingContext {
            is_deleted,
            prev_access: prev_data.access,
        };
        update_right_set(id, new_data, proc_ctx, aux_data, ctx, cache_ctx)?;
    }

    if !removed_resource.is_empty() {
        // If there are removed resources, update the access right set for those resources
        let t_data = RightData {
            resource: &removed_resource,
            in_set: new_data.in_set,
            access: new_data.access,
        };
        let proc_ctx = ProcessingContext {
            is_deleted: true,
            prev_access: prev_data.access,
        };
        update_right_set(id, &t_data, proc_ctx, aux_data, ctx, cache_ctx)?;
    }

    if !removed_in_set.is_empty() {
        // If there are removed groups, update the access right set for those groups
        let t_data = RightData {
            resource: new_data.resource,
            in_set: &removed_in_set,
            access: new_data.access,
        };
        let proc_ctx = ProcessingContext {
            is_deleted: true,
            prev_access: prev_data.access,
        };
        update_right_set(id, &t_data, proc_ctx, aux_data, ctx, cache_ctx)?;
    }

    Ok(())
}

// Function for updating an access right set
// - For each resource, it generates a key based on the prefix, filter, and resource identifier.
// - Retrieves the previous access right set from the cache or storage.
// - Updates the access right set based on the new data and deletion flag.
// - Saves the updated access right set to the cache or storage.
fn update_right_set(
    source_id: &str,
    new_data: &RightData,
    proc_ctx: ProcessingContext,
    aux_data: &AuxData,
    ctx: &mut Context,
    cache_ctx: &mut CacheContext,
) -> Result<(), StorageError> {
    for rs in new_data.resource.iter() {
        // Generate the key based on the prefix, filter, and resource identifier
        let key = aux_data.prefix.to_owned() + aux_data.use_filter + rs;

        debug!("APPLY ACCESS = {}", new_data.access);
        if proc_ctx.is_deleted {
            debug!("IS DELETED");
        }

        let mut new_right_set = ACLRecordSet::new();

        // Retrieve the previous access right set from the cache or storage
        if let Some(prev_data_str) = cache_ctx.cache.get(&key) {
            debug!("PRE(MEM): {} {} {:?}", source_id, rs, prev_data_str);
            decode_rec_to_rightset(prev_data_str, &mut new_right_set);
        } else if let Some(prev_data_str) = ctx.storage.get(&key) {
            debug!("PRE(STORAGE): {} {} {:?}", source_id, rs, prev_data_str);
            decode_rec_to_rightset(&prev_data_str, &mut new_right_set);
        }

        // Update the access right set based on the new data and deletion flag
        for in_set_id in new_data.in_set.iter() {
            if let Some(rr) = new_right_set.get_mut(in_set_id) {
                rr.is_deleted = proc_ctx.is_deleted;
                rr.marker = aux_data.marker;
                if aux_data.is_drop_count {
                    rr.access = update_counters(&mut rr.counters, proc_ctx.prev_access, new_data.access, proc_ctx.is_deleted, aux_data.is_drop_count);
                    if rr.access != 0 && !rr.counters.is_empty() {
                        rr.is_deleted = false;
                    }
                } else if proc_ctx.is_deleted {
                    rr.access = update_counters(&mut rr.counters, proc_ctx.prev_access, rr.access | proc_ctx.prev_access, proc_ctx.is_deleted, false);
                    if rr.access != 0 && !rr.counters.is_empty() {
                        rr.is_deleted = false;
                    }
                } else {
                    rr.access = update_counters(&mut rr.counters, proc_ctx.prev_access, new_data.access, proc_ctx.is_deleted, false);
                }
            } else {
                new_right_set.insert(
                    in_set_id.to_string(),
                    ACLRecord {
                        id: in_set_id.to_string(),
                        access: new_data.access,
                        marker: aux_data.marker,
                        is_deleted: proc_ctx.is_deleted,
                        level: 0,
                        counters: HashMap::default(),
                    },
                );
            }
        }

        let new_record = encode_record(None, &new_right_set, ctx.version_of_index_format);

        // Save the updated access right set to the cache or storage
        if *cache_ctx.mode == CacheType::Write {
            debug!("NEW(MEM): {} {} {:?}", source_id, rs, new_record);
            cache_ctx.cache.insert(key, new_record);
        } else {
            // Write to either Tarantool or LMDB, not both
            if let Some(tt) = &ctx.tarantool_indexer {
                debug!("NEW(TARANTOOL): {} {} {:?}", source_id, rs, new_record);
                if !tt.put(&key, &new_record) {
                    return Err(StorageError::StoragePutError {
                        key: key.clone(),
                        source: "tarantool".to_string(),
                    });
                }
            } else {
                debug!("NEW(STORAGE): {} {} {:?}", source_id, rs, new_record);
                
                if !ctx.storage.put(&key, &new_record) {
                    return Err(StorageError::StoragePutError {
                        key: key.clone(),
                        source: "storage".to_string(),
                    });
                }

                if let Some(c) = &mut ctx.acl_cache {
                    let new_record = encode_record(Some(Utc::now()), &new_right_set, ctx.version_of_index_format);
                    debug!("NEW(CACHE): {} {} {:?}", source_id, rs, new_record);
                    
                    if !c.instance.put(&key, new_record) {
                        return Err(StorageError::StoragePutError {
                            key: key.clone(),
                            source: "acl_cache".to_string(),
                        });
                    }
                }
            }
        }
    }
    Ok(())
}

// Function to get the elements that are in array a but not in array b
pub fn get_disappeared(a: &[String], b: &[String]) -> Vec<String> {
    let mut delta = Vec::new();

    for r_a in a.iter() {
        let mut is_found = false;
        for r_b in b.iter() {
            if r_a == r_b {
                is_found = true;
                break;
            }
        }

        if !is_found {
            delta.push(r_a.clone());
        }
    }

    if !delta.is_empty() {
        warn!("### disappeared A B, {:?}", delta);
    }
    delta
}

pub fn prepare_permission_statement(prev_state: &mut Individual, new_state: &mut Individual, ctx: &mut Context) -> Result<(), StorageError> {
    index_right_sets(prev_state, new_state, "v-s:permissionObject", "v-s:permissionSubject", PERMISSION_PREFIX, 0, ctx)
}
