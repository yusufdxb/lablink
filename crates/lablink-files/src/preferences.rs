//! Private, versioned GUI preferences. No addresses, keys or passwords.
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    path::{Path, PathBuf},
};
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Locations {
    pub local: Option<String>,
    pub remote: Option<String>,
    pub local_favorites: Vec<String>,
    pub remote_favorites: Vec<String>,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Preferences {
    /// Desktop appearance; absent in older preferences means True Black.
    #[serde(default)]
    pub appearance: String,
    pub devices: BTreeMap<String, Locations>,
}
impl Preferences {
    pub fn path() -> PathBuf {
        lablink_core::paths::default_state_dir().join("files-preferences.json")
    }
    pub fn load(path: &Path) -> Result<Self> {
        let file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(e.into()),
        };
        if file.metadata()?.len() > 1024 * 1024 {
            return Err(Error::Refused("Files preferences exceed size limit".into()));
        }
        let mut data = Vec::new();
        file.take(1024 * 1024 + 1).read_to_end(&mut data)?;
        if data.len() > 1024 * 1024 {
            return Err(Error::Refused("Files preferences exceed size limit".into()));
        }
        serde_json::from_slice(&data)
            .map_err(|_| Error::Refused("Invalid Files preferences".into()))
    }
    pub fn save(&self, path: &Path) -> Result<()> {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let parent = path
            .parent()
            .ok_or_else(|| Error::Refused("Preferences need a parent directory".into()))?;
        std::fs::create_dir_all(parent)?;
        let temporary = parent.join(format!(".files-preferences-{}", uuid::Uuid::new_v4()));
        let result = (|| {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temporary)?;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            let data = serde_json::to_vec(self)
                .map_err(|_| Error::Refused("Cannot serialize Files preferences".into()))?;
            if data.len() > 1024 * 1024 {
                return Err(Error::Refused("Files preferences exceed size limit".into()));
            }
            file.write_all(&data)?;
            file.sync_all()?;
            std::fs::rename(&temporary, path)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(temporary);
        }
        result
    }
}
