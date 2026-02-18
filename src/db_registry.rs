//! DB registry: maps aliases and numeric indices to database file paths.
//!
//! Registry is stored at `~/.topo/db_registry.json` (overridden by
//! `TOPO_REGISTRY_DIR` env var for tests).

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbEntry {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default)]
    pub is_default: bool,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DbRegistry {
    pub entries: Vec<DbEntry>,
}

fn registry_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("TOPO_REGISTRY_DIR") {
        return PathBuf::from(dir);
    }
    let home = std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."));
    home.join(".topo")
}

fn registry_path() -> PathBuf {
    registry_dir().join("db_registry.json")
}

fn current_timestamp_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

impl DbRegistry {
    pub fn load() -> Self {
        let path = registry_path();
        match std::fs::read_to_string(&path) {
            Ok(contents) => serde_json::from_str(&contents).unwrap_or_default(),
            Err(_) => DbRegistry::default(),
        }
    }

    pub fn save(&self) -> Result<(), String> {
        let path = registry_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create registry dir: {}", e))?;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("failed to serialize registry: {}", e))?;
        std::fs::write(&path, json)
            .map_err(|e| format!("failed to write registry: {}", e))?;
        Ok(())
    }

    pub fn add(&mut self, db_path: &str, name: Option<&str>) -> Result<(), String> {
        // Normalize to absolute path
        let abs = Self::normalize_path(db_path);

        // Check for duplicate path
        if self.entries.iter().any(|e| e.path == abs) {
            return Err(format!("path already registered: {}", abs));
        }

        // Check for duplicate name
        if let Some(n) = name {
            if self.entries.iter().any(|e| e.name.as_deref() == Some(n)) {
                return Err(format!("name already in use: {}", n));
            }
        }

        let is_default = self.entries.is_empty();
        self.entries.push(DbEntry {
            path: abs,
            name: name.map(|s| s.to_string()),
            is_default,
            created_at: current_timestamp_ms(),
        });
        Ok(())
    }

    pub fn remove(&mut self, selector: &str) -> Result<DbEntry, String> {
        let idx = self.find_index(selector)?;
        let entry = self.entries.remove(idx);

        // If removed entry was default and entries remain, make first one default
        if entry.is_default && !self.entries.is_empty() {
            self.entries[0].is_default = true;
        }
        Ok(entry)
    }

    pub fn rename(&mut self, selector: &str, new_name: &str) -> Result<(), String> {
        // Check for duplicate name
        if self.entries.iter().any(|e| e.name.as_deref() == Some(new_name)) {
            return Err(format!("name already in use: {}", new_name));
        }
        let idx = self.find_index(selector)?;
        self.entries[idx].name = Some(new_name.to_string());
        Ok(())
    }

    pub fn set_default(&mut self, selector: &str) -> Result<(), String> {
        let idx = self.find_index(selector)?;
        for e in &mut self.entries {
            e.is_default = false;
        }
        self.entries[idx].is_default = true;
        Ok(())
    }

    /// Resolve a selector to a DB path. Priority:
    /// 1. Existing file path
    /// 2. Exact alias name match
    /// 3. 1-based numeric index
    pub fn resolve(&self, selector: &str) -> Result<String, String> {
        // 1. If it looks like a file path and exists, use it directly
        if Path::new(selector).exists() {
            return Ok(Self::normalize_path(selector));
        }

        // 2. Exact alias match
        if let Some(entry) = self.entries.iter().find(|e| e.name.as_deref() == Some(selector)) {
            return Ok(entry.path.clone());
        }

        // 3. Numeric index (1-based)
        if let Ok(idx) = selector.parse::<usize>() {
            if idx >= 1 && idx <= self.entries.len() {
                return Ok(self.entries[idx - 1].path.clone());
            }
            return Err(format!(
                "invalid index {}; available: 1-{}",
                idx,
                self.entries.len()
            ));
        }

        // Not found — treat as a new path (for create-workspace etc.)
        Ok(selector.to_string())
    }

    /// Get the default entry path, if one exists.
    pub fn default_path(&self) -> Option<&str> {
        self.entries
            .iter()
            .find(|e| e.is_default)
            .map(|e| e.path.as_str())
    }

    fn find_index(&self, selector: &str) -> Result<usize, String> {
        // By name
        if let Some(idx) = self.entries.iter().position(|e| e.name.as_deref() == Some(selector)) {
            return Ok(idx);
        }

        // By 1-based index
        if let Ok(idx) = selector.parse::<usize>() {
            if idx >= 1 && idx <= self.entries.len() {
                return Ok(idx - 1);
            }
            return Err(format!(
                "invalid index {}; available: 1-{}",
                idx,
                self.entries.len()
            ));
        }

        // By path
        let abs = Self::normalize_path(selector);
        if let Some(idx) = self.entries.iter().position(|e| e.path == abs) {
            return Ok(idx);
        }

        Err(format!("not found: {}", selector))
    }

    fn normalize_path(p: &str) -> String {
        let path = Path::new(p);
        if path.is_absolute() {
            p.to_string()
        } else {
            std::env::current_dir()
                .unwrap_or_default()
                .join(path)
                .to_str()
                .unwrap_or(p)
                .to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Serialize tests that modify TOPO_REGISTRY_DIR env var
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_test_registry<F: FnOnce()>(f: F) {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("TOPO_REGISTRY_DIR", dir.path().to_str().unwrap());
        f();
        std::env::remove_var("TOPO_REGISTRY_DIR");
    }

    #[test]
    fn test_add_list_remove() {
        with_test_registry(|| {
            let mut reg = DbRegistry::default();
            reg.add("/tmp/test.db", Some("test")).unwrap();
            assert_eq!(reg.entries.len(), 1);
            assert_eq!(reg.entries[0].name.as_deref(), Some("test"));
            assert!(reg.entries[0].is_default);

            reg.add("/tmp/test2.db", Some("test2")).unwrap();
            assert_eq!(reg.entries.len(), 2);
            assert!(!reg.entries[1].is_default);

            let removed = reg.remove("test").unwrap();
            assert_eq!(removed.path, "/tmp/test.db");
            assert_eq!(reg.entries.len(), 1);
            // Remaining entry should now be default
            assert!(reg.entries[0].is_default);
        });
    }

    #[test]
    fn test_rename() {
        with_test_registry(|| {
            let mut reg = DbRegistry::default();
            reg.add("/tmp/test.db", Some("old")).unwrap();
            reg.rename("old", "new").unwrap();
            assert_eq!(reg.entries[0].name.as_deref(), Some("new"));
        });
    }

    #[test]
    fn test_set_default() {
        with_test_registry(|| {
            let mut reg = DbRegistry::default();
            reg.add("/tmp/a.db", Some("a")).unwrap();
            reg.add("/tmp/b.db", Some("b")).unwrap();
            assert!(reg.entries[0].is_default);
            assert!(!reg.entries[1].is_default);

            reg.set_default("b").unwrap();
            assert!(!reg.entries[0].is_default);
            assert!(reg.entries[1].is_default);
        });
    }

    #[test]
    fn test_resolve_by_name() {
        with_test_registry(|| {
            let mut reg = DbRegistry::default();
            reg.add("/tmp/test.db", Some("mydb")).unwrap();
            assert_eq!(reg.resolve("mydb").unwrap(), "/tmp/test.db");
        });
    }

    #[test]
    fn test_resolve_by_index() {
        with_test_registry(|| {
            let mut reg = DbRegistry::default();
            reg.add("/tmp/a.db", Some("a")).unwrap();
            reg.add("/tmp/b.db", Some("b")).unwrap();
            assert_eq!(reg.resolve("1").unwrap(), "/tmp/a.db");
            assert_eq!(reg.resolve("2").unwrap(), "/tmp/b.db");
        });
    }

    #[test]
    fn test_resolve_by_existing_path() {
        with_test_registry(|| {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("exists.db");
            std::fs::write(&path, b"").unwrap();

            let reg = DbRegistry::default();
            let resolved = reg.resolve(path.to_str().unwrap()).unwrap();
            assert_eq!(resolved, path.to_str().unwrap());
        });
    }

    #[test]
    fn test_save_and_load() {
        with_test_registry(|| {
            let mut reg = DbRegistry::default();
            reg.add("/tmp/persist.db", Some("persist")).unwrap();
            reg.save().unwrap();

            let loaded = DbRegistry::load();
            assert_eq!(loaded.entries.len(), 1);
            assert_eq!(loaded.entries[0].name.as_deref(), Some("persist"));
        });
    }

    #[test]
    fn test_duplicate_name_rejected() {
        with_test_registry(|| {
            let mut reg = DbRegistry::default();
            reg.add("/tmp/a.db", Some("dup")).unwrap();
            assert!(reg.add("/tmp/b.db", Some("dup")).is_err());
        });
    }

    #[test]
    fn test_duplicate_path_rejected() {
        with_test_registry(|| {
            let mut reg = DbRegistry::default();
            reg.add("/tmp/same.db", Some("a")).unwrap();
            assert!(reg.add("/tmp/same.db", Some("b")).is_err());
        });
    }
}
