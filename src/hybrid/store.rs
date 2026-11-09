//! On-disk store of linked ("known") phones.
//!
//! `pxp` calls [`PxpKnownDeviceInfoStore::put_known_device`] when a phone
//! sends linking information after a QR session and
//! [`PxpKnownDeviceInfoStore::delete_known_device`] when the tunnel service
//! reports the link is gone. Listing is ours. The file lives at
//! `$XDG_DATA_HOME/pocketkey/linked_devices.cbor` (default
//! `~/.local/share/...`), directory 0700, file 0600, written atomically.
//! The link secret inside grants the ability to wake the phone for a
//! passkey prompt, so treat the file like a password.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use pxp::known_devices::{PxpKnownDeviceId, PxpKnownDeviceInfo, PxpKnownDeviceInfoStore};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

/// One linked phone as persisted. Mirrors `PxpKnownDeviceInfo` plus bookkeeping.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredDevice {
    #[serde(with = "serde_bytes")]
    pub contact_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub link_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub link_secret: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub public_key: Vec<u8>,
    pub name: String,
    pub tunnel_domain: String,
    /// Unix seconds; when the link was created or last used successfully.
    pub last_used: u64,
}

impl StoredDevice {
    fn from_info(info: &PxpKnownDeviceInfo, last_used: u64) -> Self {
        Self {
            contact_id: info.contact_id.clone(),
            link_id: info.link_id.to_vec(),
            link_secret: info.link_secret.to_vec(),
            public_key: info.public_key.to_vec(),
            name: info.name.clone(),
            tunnel_domain: info.tunnel_domain.clone(),
            last_used,
        }
    }

    pub fn to_info(&self) -> Option<PxpKnownDeviceInfo> {
        Some(PxpKnownDeviceInfo {
            contact_id: self.contact_id.clone(),
            link_id: self.link_id.as_slice().try_into().ok()?,
            link_secret: self.link_secret.as_slice().try_into().ok()?,
            public_key: self.public_key.as_slice().try_into().ok()?,
            name: self.name.clone(),
            tunnel_domain: self.tunnel_domain.clone(),
        })
    }
}

#[derive(Debug)]
pub struct FileStore {
    path: PathBuf,
    devices: Mutex<BTreeMap<PxpKnownDeviceId, StoredDevice>>,
}

impl FileStore {
    /// Default location under `$XDG_DATA_HOME` (or `~/.local/share`).
    pub fn default_path() -> io::Result<PathBuf> {
        let base = match std::env::var_os("XDG_DATA_HOME") {
            Some(dir) if !dir.is_empty() => PathBuf::from(dir),
            _ => {
                let home = std::env::var_os("HOME")
                    .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "HOME is not set"))?;
                PathBuf::from(home).join(".local/share")
            }
        };
        Ok(base.join("pocketkey").join("linked_devices.cbor"))
    }

    /// Load the store from `path`, creating the parent directory (0700) if needed.
    pub fn open(path: PathBuf) -> io::Result<Self> {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        }
        let devices = match fs::read(&path) {
            Ok(bytes) => {
                match ciborium::from_reader::<BTreeMap<String, StoredDevice>, _>(bytes.as_slice()) {
                    Ok(map) => map,
                    Err(e) => {
                        warn!(path = %path.display(), error = %e, "linked device store is unreadable; starting empty");
                        BTreeMap::new()
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => return Err(e),
        };
        debug!(path = %path.display(), count = devices.len(), "linked device store loaded");
        Ok(Self {
            path,
            devices: Mutex::new(devices),
        })
    }

    /// Linked phones, most recently used first.
    pub fn list(&self) -> Vec<(PxpKnownDeviceId, StoredDevice)> {
        let devices = self.devices.lock().unwrap_or_else(|p| p.into_inner());
        let mut all: Vec<_> = devices
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        all.sort_by_key(|(_, d)| std::cmp::Reverse(d.last_used));
        all
    }

    /// Record a successful use so this phone is tried first next time.
    pub fn touch(&self, id: &PxpKnownDeviceId) {
        let mut devices = self.devices.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(d) = devices.get_mut(id) {
            d.last_used = now_secs();
        }
        if let Err(e) = write_atomically(&self.path, &devices) {
            warn!(error = %e, "could not update linked device store");
        }
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn write_atomically(path: &Path, devices: &BTreeMap<String, StoredDevice>) -> io::Result<()> {
    let tmp = path.with_extension("cbor.tmp");
    {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        ciborium::into_writer(devices, &mut file).map_err(io::Error::other)?;
        file.sync_all()?;
    }
    fs::rename(&tmp, path)
}

#[async_trait]
impl PxpKnownDeviceInfoStore for FileStore {
    async fn put_known_device(&self, device_id: &PxpKnownDeviceId, device: &PxpKnownDeviceInfo) {
        info!(name = %device.name, "phone linked; it can be used without a QR code from now on");
        let mut devices = self.devices.lock().unwrap_or_else(|p| p.into_inner());
        devices.insert(
            device_id.clone(),
            StoredDevice::from_info(device, now_secs()),
        );
        if let Err(e) = write_atomically(&self.path, &devices) {
            warn!(error = %e, "could not persist linked phone");
        }
    }

    async fn delete_known_device(&self, device_id: &PxpKnownDeviceId) {
        let mut devices = self.devices.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(d) = devices.remove(device_id) {
            info!(name = %d.name, "phone unlinked (tunnel service reports the link is gone)");
            if let Err(e) = write_atomically(&self.path, &devices) {
                warn!(error = %e, "could not persist linked phone removal");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(name: &str) -> PxpKnownDeviceInfo {
        PxpKnownDeviceInfo {
            contact_id: vec![1, 2, 3],
            link_id: [7; 8],
            link_secret: [9; 32],
            public_key: [4; 65],
            name: name.into(),
            tunnel_domain: "cable.ua5v.com".into(),
        }
    }

    fn temp_path(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("pocketkey-test-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir.join("sub").join("linked_devices.cbor")
    }

    #[tokio::test]
    async fn put_persists_with_restrictive_permissions_and_round_trips() {
        let path = temp_path("put");
        let store = FileStore::open(path.clone()).unwrap();
        assert!(store.list().is_empty());
        store
            .put_known_device(&"abc".to_string(), &sample("Pixel"))
            .await;

        let dir_mode = fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700);
        let file_mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o600);

        let reloaded = FileStore::open(path.clone()).unwrap();
        let list = reloaded.list();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].0, "abc");
        assert_eq!(list[0].1.to_info().unwrap().name, "Pixel");
        assert_eq!(list[0].1.to_info().unwrap().link_secret, [9; 32]);
        fs::remove_dir_all(path.parent().unwrap().parent().unwrap()).unwrap();
    }

    #[tokio::test]
    async fn delete_and_ordering_by_last_used() {
        let path = temp_path("del");
        let store = FileStore::open(path.clone()).unwrap();
        store.put_known_device(&"a".to_string(), &sample("A")).await;
        store.put_known_device(&"b".to_string(), &sample("B")).await;
        // Force a deterministic order: make "a" the most recent.
        {
            let mut d = store.devices.lock().unwrap();
            d.get_mut("a").unwrap().last_used = 2;
            d.get_mut("b").unwrap().last_used = 1;
        }
        assert_eq!(
            store
                .list()
                .iter()
                .map(|(id, _)| id.as_str())
                .collect::<Vec<_>>(),
            ["a", "b"]
        );
        store.touch(&"b".to_string());
        assert_eq!(store.list()[0].0, "b");
        store.delete_known_device(&"b".to_string()).await;
        assert_eq!(store.list().len(), 1);
        let reloaded = FileStore::open(path.clone()).unwrap();
        assert_eq!(reloaded.list().len(), 1);
        fs::remove_dir_all(path.parent().unwrap().parent().unwrap()).unwrap();
    }

    #[test]
    fn corrupt_file_starts_empty() {
        let path = temp_path("corrupt");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, b"not cbor at all \xff\xff").unwrap();
        let store = FileStore::open(path.clone()).unwrap();
        assert!(store.list().is_empty());
        fs::remove_dir_all(path.parent().unwrap().parent().unwrap()).unwrap();
    }
}
