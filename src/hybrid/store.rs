//! On-disk store of linked ("known") phones.
//!
//! `pxp` calls [`PxpKnownDeviceInfoStore::put_known_device`] when a phone
//! sends linking information after a QR session and
//! [`PxpKnownDeviceInfoStore::delete_known_device`] when the tunnel service
//! reports the link is gone. The file lives at
//! `$XDG_DATA_HOME/pocketkey/linked_devices.cbor` (default
//! `~/.local/share/...`), directory 0700, file 0600, written atomically.
//! The link secret inside grants the ability to wake the phone for a
//! passkey prompt, so treat the file like a password.
//!
//! Disk is authoritative: every lookup and mutation reloads the file while
//! holding the store lock. Unlinking it revokes previously stored links before
//! the next lookup; a late `touch` or unrelated linking callback cannot restore
//! them. Directory locks also serialize cooperating store instances/processes.
//! External unlink/replacement does not take that lock: we check for changes
//! again immediately before rename, but cannot make that check and rename
//! atomic with an external `rm`. Stop pocketkey before removing the file for
//! guaranteed revocation, including in-flight connections/linking callbacks.
//! Already returned device records and ongoing phone connections are not revoked.

use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use pxp::known_devices::{PxpKnownDeviceId, PxpKnownDeviceInfo, PxpKnownDeviceInfoStore};
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use tracing::{debug, info, warn};

const MAX_STORE_BYTES: usize = 1024 * 1024;
const MAX_DEVICES: usize = 128;
const MAX_DEVICE_ID_BYTES: usize = 256;
const MAX_CONTACT_ID_BYTES: usize = 4096;
const MAX_NAME_BYTES: usize = 1024;
const MAX_DOMAIN_BYTES: usize = 253;
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

type Devices = BTreeMap<PxpKnownDeviceId, StoredDevice>;

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
        validate_lengths("", &self.contact_id, &self.name, &self.tunnel_domain).ok()?;
        Some(PxpKnownDeviceInfo {
            contact_id: self.contact_id.clone(),
            link_id: self.link_id.as_slice().try_into().ok()?,
            link_secret: self.link_secret.as_slice().try_into().ok()?,
            public_key: self.public_key.as_slice().try_into().ok()?,
            name: self.name.clone(),
            tunnel_domain: self.tunnel_domain.clone(),
        })
    }

    fn validate(&self, id: &str) -> io::Result<()> {
        validate_lengths(id, &self.contact_id, &self.name, &self.tunnel_domain)?;
        if self.link_id.len() != 8 || self.link_secret.len() != 32 || self.public_key.len() != 65 {
            return Err(invalid_data("invalid linked device key lengths"));
        }
        Ok(())
    }
}

fn validate_lengths(id: &str, contact_id: &[u8], name: &str, domain: &str) -> io::Result<()> {
    if id.len() > MAX_DEVICE_ID_BYTES
        || contact_id.len() > MAX_CONTACT_ID_BYTES
        || name.len() > MAX_NAME_BYTES
        || domain.len() > MAX_DOMAIN_BYTES
    {
        return Err(invalid_data("linked device fields exceed size limits"));
    }
    Ok(())
}

/// Deserialize incrementally rather than building an unbounded map first.
struct BoundedDevices(Devices);

impl<'de> Deserialize<'de> for BoundedDevices {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct DeviceVisitor;
        impl<'de> Visitor<'de> for DeviceVisitor {
            type Value = BoundedDevices;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a bounded linked device map")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut input: A) -> Result<Self::Value, A::Error> {
                if input.size_hint().is_some_and(|len| len > MAX_DEVICES) {
                    return Err(de::Error::custom("too many linked devices"));
                }
                let mut devices = Devices::new();
                while let Some(id) = input.next_key::<String>()? {
                    if devices.len() >= MAX_DEVICES {
                        return Err(de::Error::custom("too many linked devices"));
                    }
                    let device: StoredDevice = input.next_value()?;
                    device.validate(&id).map_err(de::Error::custom)?;
                    if devices.insert(id, device).is_some() {
                        return Err(de::Error::custom("duplicate linked device id"));
                    }
                }
                Ok(BoundedDevices(devices))
            }
        }
        deserializer.deserialize_map(DeviceVisitor)
    }
}

#[derive(Debug)]
pub struct FileStore {
    path: PathBuf,
    // No long-lived device cache: stale callbacks must never flush old links.
    access: Mutex<()>,
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

    /// Load the store, creating missing directories privately. Existing unsafe
    /// directories/files are rejected, not silently chmod'ed or followed.
    pub fn open(path: PathBuf) -> io::Result<Self> {
        let parent = parent_directory(&path);
        check_ancestors(parent)?;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
        let store = Self {
            path,
            access: Mutex::new(()),
        };
        let devices = store.read_devices()?;
        debug!(path = %store.path.display(), count = devices.len(), "linked device store loaded");
        Ok(store)
    }

    fn read_devices(&self) -> io::Result<Devices> {
        let _guard = self.access.lock().unwrap_or_else(|p| p.into_inner());
        let directory = StoreDirectory::open(&self.path)?;
        directory.read_devices().map(|(devices, _)| devices)
    }

    fn update(&self, change: impl FnOnce(&mut Devices) -> io::Result<bool>) -> io::Result<()> {
        let _guard = self.access.lock().unwrap_or_else(|p| p.into_inner());
        let directory = StoreDirectory::open(&self.path)?;
        let (mut devices, stamp) = directory.read_devices()?;
        if change(&mut devices)? {
            directory.write_atomically(&devices, stamp)?;
        }
        Ok(())
    }

    /// Linked phones, most recently used first. Unreadable/unsafe stores fail closed.
    pub fn list(&self) -> Vec<(PxpKnownDeviceId, StoredDevice)> {
        let devices = self.read_devices().unwrap_or_else(|e| {
            warn!(error = %e, "could not read linked device store; ignoring stored links");
            Devices::new()
        });
        let mut all: Vec<_> = devices.into_iter().collect();
        all.sort_by_key(|(_, d)| std::cmp::Reverse(d.last_used));
        all
    }

    /// Look up a phone against the current file, not a previously returned list.
    pub fn get(&self, id: &str) -> Option<StoredDevice> {
        match self.read_devices() {
            Ok(mut devices) => devices.remove(id),
            Err(e) => {
                warn!(error = %e, "could not read linked device store; ignoring stored links");
                None
            }
        }
    }

    /// Record a successful use without recreating a removed link or store.
    pub fn touch(&self, id: &PxpKnownDeviceId) {
        if let Err(e) = self.update(|devices| {
            let Some(device) = devices.get_mut(id) else {
                return Ok(false);
            };
            device.last_used = now_secs();
            Ok(true)
        }) {
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

fn invalid_data(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn unsafe_path(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

fn current_uid() -> u32 {
    // SAFETY: geteuid has no arguments or memory-safety preconditions.
    unsafe { libc::geteuid() }
}

fn parent_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

/// XDG bases/home ancestors may be 0755 or symlinks; do not chmod them or
/// demand that they be private. They must not let another uid replace children.
/// Root-owned sticky temporary directories are safe ancestors of our own dirs.
fn check_ancestors(path: &Path) -> io::Result<()> {
    for ancestor in path.ancestors() {
        let ancestor = if ancestor.as_os_str().is_empty() {
            Path::new(".")
        } else {
            ancestor
        };
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) if metadata.uid() != current_uid() && metadata.uid() != 0 => {
                // In a sticky directory, a foreign symlink's owner could still
                // redirect it even if its current target is safe.
                return Err(unsafe_path(
                    "linked device store ancestor has a foreign owner",
                ));
            }
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        }
        let resolved = fs::canonicalize(ancestor)?;
        // Check both the lexical path and symlink destinations' ancestors.
        for directory in resolved.ancestors() {
            let metadata = fs::metadata(directory)?;
            if !metadata.is_dir()
                || (metadata.uid() != current_uid() && metadata.uid() != 0)
                || (metadata.mode() & 0o022 != 0 && metadata.mode() & libc::S_ISVTX == 0)
            {
                return Err(unsafe_path("unsafe linked device store ancestor directory"));
            }
        }
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct FileStamp {
    device: u64,
    inode: u64,
    size: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl FileStamp {
    fn of(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.len(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        }
    }
}

/// All operations are relative to a verified directory descriptor, so a renamed
/// parent cannot redirect temp creation/rename/cleanup into another directory.
struct StoreDirectory {
    file: File,
    name: CString,
}

impl StoreDirectory {
    fn open(path: &Path) -> io::Result<Self> {
        let parent = parent_directory(path);
        check_ancestors(parent)?;
        let name = CString::new(
            path.file_name()
                .ok_or_else(|| invalid_data("store path has no filename"))?
                .as_bytes(),
        )
        .map_err(|_| invalid_data("store filename contains NUL"))?;
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(parent)?;
        let metadata = file.metadata()?;
        if !metadata.is_dir() || metadata.uid() != current_uid() || metadata.mode() & 0o077 != 0 {
            return Err(unsafe_path("linked device store directory must be owned by the current user and private (0700)"));
        }
        // Lock the directory, not the file that is replaced at every commit.
        loop {
            // SAFETY: file owns this valid descriptor throughout the call.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {
                break;
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
        // Closing file releases this advisory lock, including on error paths.
        Ok(Self { file, name })
    }

    fn open_at(&self, name: &CString, flags: libc::c_int) -> io::Result<File> {
        // SAFETY: name is NUL-terminated; the directory descriptor is live. The
        // mode is used only with O_CREAT. Successful openat returns a new fd.
        let fd = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fd is newly opened and ownership is transferred exactly once.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    fn open_store(&self) -> io::Result<Option<(File, FileStamp)>> {
        // NONBLOCK prevents a malicious FIFO from hanging before fstat rejects it.
        let file = match self.open_at(
            &self.name,
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        ) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != current_uid()
            || metadata.mode() & 0o7777 & !0o600 != 0
            || metadata.nlink() != 1
        {
            return Err(unsafe_path("linked device store must be a private, singly linked regular file owned by the current user (0600)"));
        }
        if metadata.len() > MAX_STORE_BYTES as u64 {
            return Err(invalid_data("linked device store exceeds size limit"));
        }
        Ok(Some((file, FileStamp::of(&metadata))))
    }

    fn read_devices(&self) -> io::Result<(Devices, Option<FileStamp>)> {
        let Some((mut file, stamp)) = self.open_store()? else {
            return Ok((Devices::new(), None));
        };
        let mut bytes = Vec::new();
        // Bound reads even if a file grows after the metadata check.
        (&mut file)
            .take(MAX_STORE_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_STORE_BYTES {
            return Err(invalid_data("linked device store exceeds size limit"));
        }
        if FileStamp::of(&file.metadata()?) != stamp {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "linked device store changed during read",
            ));
        }
        let mut input = bytes.as_slice();
        let devices: BoundedDevices = ciborium::from_reader(&mut input)
            .map_err(|e| invalid_data(&format!("invalid linked device store: {e}")))?;
        if !input.is_empty() {
            return Err(invalid_data("trailing data in linked device store"));
        }
        Ok((devices.0, Some(stamp)))
    }

    fn write_atomically(&self, devices: &Devices, expected: Option<FileStamp>) -> io::Result<()> {
        if devices.len() > MAX_DEVICES {
            return Err(invalid_data("too many linked devices"));
        }
        for (id, device) in devices {
            device.validate(id)?;
        }
        let mut bytes = Vec::new();
        ciborium::into_writer(devices, &mut bytes).map_err(io::Error::other)?;
        if bytes.len() > MAX_STORE_BYTES {
            return Err(invalid_data("linked device store exceeds size limit"));
        }
        let mut temp = self.create_temp()?;
        temp.file.write_all(&bytes)?;
        temp.file.sync_all()?;
        if self.open_store()?.map(|(_, stamp)| stamp) != expected {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "linked device store was externally removed or replaced; update discarded",
            ));
        }
        // Best effort against external rm: it can still race this final rename.
        // SAFETY: both names are NUL-terminated and the directory fd is live.
        if unsafe {
            libc::renameat(
                self.file.as_raw_fd(),
                temp.name.as_ptr(),
                self.file.as_raw_fd(),
                self.name.as_ptr(),
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        temp.renamed = true;
        self.file.sync_all()
    }

    fn create_temp(&self) -> io::Result<TemporaryFile<'_>> {
        for _ in 0..128 {
            let name = CString::new(format!(
                ".linked_devices.{}.{}.tmp",
                std::process::id(),
                NEXT_TEMP.fetch_add(1, Ordering::Relaxed),
            ))
            .expect("temporary filename cannot contain NUL");
            match self.open_at(
                &name,
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
            ) {
                Ok(file) => {
                    let temp = TemporaryFile {
                        directory: self,
                        name,
                        file,
                        renamed: false,
                    };
                    // Safe to chmod only this newly and exclusively created fd;
                    // never alter an existing file's permissions or follow a link.
                    temp.file
                        .set_permissions(fs::Permissions::from_mode(0o600))?;
                    return Ok(temp);
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not create a unique linked device temporary file",
        ))
    }
}

struct TemporaryFile<'a> {
    directory: &'a StoreDirectory,
    name: CString,
    file: File,
    renamed: bool,
}

impl Drop for TemporaryFile<'_> {
    fn drop(&mut self) {
        if !self.renamed {
            // SAFETY: the name and borrowed directory outlive this cleanup.
            unsafe {
                libc::unlinkat(self.directory.file.as_raw_fd(), self.name.as_ptr(), 0);
            }
        }
    }
}

#[async_trait]
impl PxpKnownDeviceInfoStore for FileStore {
    async fn put_known_device(&self, device_id: &PxpKnownDeviceId, device: &PxpKnownDeviceInfo) {
        let result = validate_lengths(
            device_id,
            &device.contact_id,
            &device.name,
            &device.tunnel_domain,
        )
        .and_then(|()| {
            self.update(|devices| {
                if devices.len() >= MAX_DEVICES && !devices.contains_key(device_id) {
                    return Err(invalid_data("too many linked devices"));
                }
                devices.insert(
                    device_id.clone(),
                    StoredDevice::from_info(device, now_secs()),
                );
                Ok(true)
            })
        });
        match result {
            Ok(()) => {
                info!(name = %device.name, "phone linked; it can be used without a QR code from now on")
            }
            Err(e) => warn!(error = %e, "could not persist linked phone"),
        }
    }

    async fn delete_known_device(&self, device_id: &PxpKnownDeviceId) {
        if let Err(e) = self.update(|devices| {
            if let Some(device) = devices.remove(device_id) {
                info!(name = %device.name, "phone unlinked (tunnel service reports the link is gone)");
                Ok(true)
            } else {
                Ok(false)
            }
        }) {
            warn!(error = %e, "could not persist linked phone removal");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::sync::{Arc, Barrier};

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

    struct TestPath(PathBuf);

    impl TestPath {
        fn new(tag: &str) -> Self {
            // Prefer the harness scratch directory when it passes the same
            // security policy; some installations make it group-writable.
            let preferred = Path::new("/tmp/opencode");
            let base = if preferred.is_dir() && check_ancestors(preferred).is_ok() {
                preferred.to_path_buf()
            } else {
                std::env::temp_dir()
            };
            let dir = base.join(format!(
                "pocketkey-store-{}-{tag}-{}",
                std::process::id(),
                NEXT_TEMP.fetch_add(1, Ordering::Relaxed),
            ));
            fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
            Self(dir.join("pocketkey").join("linked_devices.cbor"))
        }

        fn parent(&self) -> &Path {
            self.0.parent().unwrap()
        }

        fn root(&self) -> &Path {
            self.parent().parent().unwrap()
        }
    }

    impl Drop for TestPath {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(self.root());
        }
    }

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    fn write_private(path: &Path, bytes: &[u8]) {
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap()
            .write_all(bytes)
            .unwrap();
    }

    fn write_records(path: &Path, devices: &Devices) {
        let mut bytes = Vec::new();
        ciborium::into_writer(devices, &mut bytes).unwrap();
        write_private(path, &bytes);
    }

    #[tokio::test]
    async fn put_persists_with_restrictive_permissions_and_round_trips() {
        let path = TestPath::new("put");
        let store = FileStore::open(path.0.clone()).unwrap();
        assert!(store.list().is_empty());
        store
            .put_known_device(&"abc".into(), &sample("Pixel"))
            .await;
        assert_eq!(mode(path.parent()), 0o700);
        assert_eq!(mode(&path.0), 0o600);

        let reloaded = FileStore::open(path.0.clone()).unwrap();
        let list = reloaded.list();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].0, "abc");
        assert_eq!(list[0].1.to_info().unwrap().name, "Pixel");
        assert_eq!(list[0].1.to_info().unwrap().link_secret, [9; 32]);
        assert_eq!(reloaded.get("abc").unwrap(), list[0].1);
        assert_eq!(fs::read_dir(path.parent()).unwrap().count(), 1);
    }

    #[tokio::test]
    async fn delete_and_ordering_by_last_used() {
        let path = TestPath::new("del");
        let store = FileStore::open(path.0.clone()).unwrap();
        store.put_known_device(&"a".into(), &sample("A")).await;
        store.put_known_device(&"b".into(), &sample("B")).await;
        store
            .update(|devices| {
                devices.get_mut("a").unwrap().last_used = 2;
                devices.get_mut("b").unwrap().last_used = 1;
                Ok(true)
            })
            .unwrap();
        assert_eq!(
            store
                .list()
                .iter()
                .map(|(id, _)| id.as_str())
                .collect::<Vec<_>>(),
            ["a", "b"]
        );
        store.touch(&"b".into());
        assert_eq!(store.list()[0].0, "b");
        store.delete_known_device(&"b".into()).await;
        assert_eq!(store.list().len(), 1);
        assert_eq!(FileStore::open(path.0.clone()).unwrap().list().len(), 1);
    }

    #[tokio::test]
    async fn unlink_revokes_before_list_and_get() {
        let path = TestPath::new("unlink-read");
        let store = FileStore::open(path.0.clone()).unwrap();
        store.put_known_device(&"old".into(), &sample("Old")).await;
        assert!(store.get("old").is_some());
        fs::remove_file(&path.0).unwrap();
        assert!(store.get("old").is_none());
        assert!(store.list().is_empty());
        assert!(!path.0.exists());
    }

    #[tokio::test]
    async fn unlink_then_touch_and_link_callback_never_restore_old_records() {
        let path = TestPath::new("unlink-write");
        let store = FileStore::open(path.0.clone()).unwrap();
        store.put_known_device(&"old".into(), &sample("Old")).await;
        fs::remove_file(&path.0).unwrap();
        // No intervening list: the mutation must itself observe deletion.
        store.touch(&"old".into());
        assert!(!path.0.exists());
        store.delete_known_device(&"old".into()).await;
        assert!(!path.0.exists());
        store.put_known_device(&"new".into(), &sample("New")).await;
        store.touch(&"old".into());
        let devices = FileStore::open(path.0.clone()).unwrap().list();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].0, "new");
    }

    #[tokio::test]
    async fn unlink_then_put_without_lookup_drops_old_records() {
        let path = TestPath::new("unlink-put");
        let store = FileStore::open(path.0.clone()).unwrap();
        store.put_known_device(&"old".into(), &sample("Old")).await;
        fs::remove_file(&path.0).unwrap();
        store.put_known_device(&"new".into(), &sample("New")).await;
        assert_eq!(store.list().len(), 1);
        assert!(store.get("old").is_none());
    }

    #[tokio::test]
    async fn external_unlink_during_update_discards_stale_snapshot() {
        let path = TestPath::new("unlink-race");
        let store = FileStore::open(path.0.clone()).unwrap();
        store.put_known_device(&"old".into(), &sample("Old")).await;
        let error = store
            .update(|devices| {
                fs::remove_file(&path.0)?;
                devices.insert("new".into(), StoredDevice::from_info(&sample("New"), 1));
                Ok(true)
            })
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert!(store.list().is_empty());
        assert_eq!(fs::read_dir(path.parent()).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn legacy_temporary_symlink_and_permissive_file_are_never_used() {
        let path = TestPath::new("tmp");
        let store = FileStore::open(path.0.clone()).unwrap();
        let victim = path.root().join("victim");
        write_private(&victim, b"do not overwrite");
        let legacy_temp = path.0.with_extension("cbor.tmp");
        symlink(&victim, &legacy_temp).unwrap();
        store.put_known_device(&"a".into(), &sample("A")).await;
        assert_eq!(fs::read(&victim).unwrap(), b"do not overwrite");
        assert!(fs::symlink_metadata(&legacy_temp).unwrap().is_symlink());
        assert_eq!(mode(&path.0), 0o600);

        fs::remove_file(&legacy_temp).unwrap();
        write_private(&legacy_temp, b"do not reuse");
        fs::set_permissions(&legacy_temp, fs::Permissions::from_mode(0o666)).unwrap();
        store.put_known_device(&"b".into(), &sample("B")).await;
        assert_eq!(fs::read(&legacy_temp).unwrap(), b"do not reuse");
        assert_eq!(mode(&legacy_temp), 0o666);
        assert_eq!(mode(&path.0), 0o600);
        assert_eq!(store.list().len(), 2);
    }

    #[test]
    fn exclusive_temp_creation_does_not_follow_or_chmod_existing_paths() {
        let path = TestPath::new("exclusive");
        let _store = FileStore::open(path.0.clone()).unwrap();
        let directory = StoreDirectory::open(&path.0).unwrap();
        let victim = path.root().join("victim");
        write_private(&victim, b"secret");
        fs::set_permissions(&victim, fs::Permissions::from_mode(0o644)).unwrap();
        let name = CString::new("collision.tmp").unwrap();
        symlink(&victim, path.parent().join("collision.tmp")).unwrap();
        let error = directory
            .open_at(
                &name,
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
            )
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&victim).unwrap(), b"secret");
        assert_eq!(mode(&victim), 0o644);
        let first = directory.create_temp().unwrap();
        let second = directory.create_temp().unwrap();
        assert_ne!(first.name, second.name);
        assert_eq!(first.file.metadata().unwrap().mode() & 0o777, 0o600);
    }

    #[tokio::test]
    async fn unsafe_file_permissions_fail_closed_and_are_not_repaired() {
        let path = TestPath::new("file-perms");
        let store = FileStore::open(path.0.clone()).unwrap();
        store.put_known_device(&"old".into(), &sample("Old")).await;
        fs::set_permissions(&path.0, fs::Permissions::from_mode(0o644)).unwrap();
        let before = fs::read(&path.0).unwrap();
        assert!(FileStore::open(path.0.clone()).is_err());
        assert!(store.list().is_empty());
        assert!(store.get("old").is_none());
        store.touch(&"old".into());
        store.put_known_device(&"new".into(), &sample("New")).await;
        assert_eq!(fs::read(&path.0).unwrap(), before);
        assert_eq!(mode(&path.0), 0o644);
    }

    #[test]
    fn symlink_hardlink_directory_and_fifo_stores_are_rejected() {
        let path = TestPath::new("file-type");
        let _store = FileStore::open(path.0.clone()).unwrap();
        let victim = path.root().join("victim");
        write_private(&victim, b"\xa0");
        symlink(&victim, &path.0).unwrap();
        assert!(FileStore::open(path.0.clone()).is_err());
        fs::remove_file(&path.0).unwrap();
        fs::hard_link(&victim, &path.0).unwrap();
        assert!(FileStore::open(path.0.clone()).is_err());
        fs::remove_file(&path.0).unwrap();
        fs::create_dir(&path.0).unwrap();
        assert!(FileStore::open(path.0.clone()).is_err());
        fs::remove_dir(&path.0).unwrap();
        let name = CString::new(path.0.as_os_str().as_bytes()).unwrap();
        // SAFETY: name is a valid NUL-terminated test pathname.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(FileStore::open(path.0.clone()).is_err());
        assert_eq!(fs::read(&victim).unwrap(), b"\xa0");
    }

    #[test]
    fn private_app_directory_required_but_xdg_base_may_be_public_or_symlinked() {
        let path = TestPath::new("directory-perms");
        fs::set_permissions(path.root(), fs::Permissions::from_mode(0o755)).unwrap();
        let _store = FileStore::open(path.0.clone()).unwrap();
        assert_eq!(mode(path.root()), 0o755);
        let alias = path.root().join("xdg-alias");
        symlink(path.root(), &alias).unwrap();
        assert!(FileStore::open(alias.join("pocketkey/linked_devices.cbor")).is_ok());
        fs::set_permissions(path.parent(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(FileStore::open(path.0.clone()).is_err());
        assert_eq!(mode(path.parent()), 0o755);
        fs::set_permissions(path.parent(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(path.root(), fs::Permissions::from_mode(0o777)).unwrap();
        assert!(FileStore::open(path.0.clone()).is_err());
        fs::set_permissions(path.root(), fs::Permissions::from_mode(0o700)).unwrap();
        let real = path.root().join("real");
        fs::rename(path.parent(), &real).unwrap();
        symlink(&real, path.parent()).unwrap();
        assert!(FileStore::open(path.0.clone()).is_err());
    }

    #[test]
    fn corrupt_trailing_oversized_and_overfull_files_are_rejected() {
        let path = TestPath::new("limits");
        let _store = FileStore::open(path.0.clone()).unwrap();
        for bytes in [b"not cbor at all \xff\xff".as_slice(), b"\xa0\x00"] {
            write_private(&path.0, bytes);
            assert!(FileStore::open(path.0.clone()).is_err());
            fs::remove_file(&path.0).unwrap();
        }
        write_private(&path.0, b"");
        fs::OpenOptions::new()
            .write(true)
            .open(&path.0)
            .unwrap()
            .set_len(MAX_STORE_BYTES as u64 + 1)
            .unwrap();
        assert!(FileStore::open(path.0.clone()).is_err());
        fs::remove_file(&path.0).unwrap();
        let devices: Devices = (0..=MAX_DEVICES)
            .map(|id| (id.to_string(), StoredDevice::from_info(&sample("Phone"), 1)))
            .collect();
        write_records(&path.0, &devices);
        assert!(FileStore::open(path.0.clone()).is_err());
    }

    #[tokio::test]
    async fn oversized_records_and_new_records_beyond_limit_are_not_persisted() {
        let path = TestPath::new("record-limits");
        let store = FileStore::open(path.0.clone()).unwrap();
        let mut oversized = sample("Phone");
        oversized.contact_id = vec![0; MAX_CONTACT_ID_BYTES + 1];
        store.put_known_device(&"bad".into(), &oversized).await;
        assert!(!path.0.exists());
        let malformed = StoredDevice::from_info(&oversized, 1);
        write_records(&path.0, &Devices::from([("bad".into(), malformed)]));
        assert!(FileStore::open(path.0.clone()).is_err());
        fs::remove_file(&path.0).unwrap();
        let devices: Devices = (0..MAX_DEVICES)
            .map(|id| (id.to_string(), StoredDevice::from_info(&sample("Phone"), 1)))
            .collect();
        write_records(&path.0, &devices);
        store
            .put_known_device(&"extra".into(), &sample("Extra"))
            .await;
        assert_eq!(store.list().len(), MAX_DEVICES);
        assert!(store.get("extra").is_none());
        store
            .put_known_device(&"0".into(), &sample("Updated"))
            .await;
        assert_eq!(store.get("0").unwrap().name, "Updated");
    }

    #[test]
    fn concurrent_instances_serialize_read_modify_write_after_unlink() {
        let path = TestPath::new("concurrent");
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let store = Arc::new(FileStore::open(path.0.clone()).unwrap());
        runtime.block_on(store.put_known_device(&"old".into(), &sample("Old")));
        let other = Arc::new(FileStore::open(path.0.clone()).unwrap());
        fs::remove_file(&path.0).unwrap();
        let barrier = Arc::new(Barrier::new(9));
        std::thread::scope(|scope| {
            for index in 0..8 {
                let store = if index % 2 == 0 {
                    store.clone()
                } else {
                    other.clone()
                };
                let barrier = barrier.clone();
                let runtime = &runtime;
                scope.spawn(move || {
                    barrier.wait();
                    store.touch(&"old".into());
                    runtime.block_on(store.put_known_device(&index.to_string(), &sample("New")));
                });
            }
            barrier.wait();
        });
        assert_eq!(store.list().len(), 8);
        assert!(other.get("old").is_none());
    }
}
