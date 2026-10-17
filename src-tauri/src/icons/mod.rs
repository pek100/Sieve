//! App icons: the icon an exe shows in Explorer, as PNG, read only and with
//! no admin. The web UI asks per app (the first exe of the app's group) and
//! falls back to its monogram while an icon loads or when there is none.
//!
//! Extraction (`win::extract`): `SHCreateItemFromParsingName` then
//! `IShellItemImageFactory::GetImage` with `SIIGBF_ICONONLY` at 32 and 64 px
//! (64 for HiDPI), read back as a 32 bpp top-down DIB with `GetDIBits`. The
//! shell hands back premultiplied alpha; PNG wants straight alpha, so the
//! colour is divided back out (`unpremultiply`).
//!
//! Cache: in memory and on disk under `<app data>/icons/`, keyed by the exe
//! path (case folded), its size and its modified time, so an updated exe gets
//! a new icon and nothing stale is shown. A missing icon is cached too (a
//! marker file), so a protected or vanished exe is not retried every render.
//! Icons never ride in the snapshot (protocol v1 stays small).

pub mod commands;
#[cfg(windows)]
mod win;

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::UNIX_EPOCH;

use serde::Serialize;

/// Icon sizes in device pixels: 1x for a 32 px box, 2x for HiDPI.
pub const SIZES: [u32; 2] = [32, 64];

/// One app's icon, PNG bytes base64 encoded, at 1x and 2x.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AppIcon {
    pub x1: String,
    pub x2: String,
}

#[derive(Debug, thiserror::Error)]
pub enum IconError {
    #[error("icon cache: {0}")]
    Io(#[from] io::Error),
    #[error("icon encode: {0}")]
    Png(#[from] png::EncodingError),
}

/// What identifies one version of one exe: path (case folded, Windows paths
/// are case insensitive), size and modified time.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    path: String,
    size: u64,
    mtime_ms: u128,
}

impl CacheKey {
    /// None when the file cannot be read (gone, or a path Windows hides).
    pub fn of(path: &Path) -> Option<CacheKey> {
        let meta = fs::metadata(path).ok()?;
        if !meta.is_file() {
            return None;
        }
        let mtime_ms = meta.modified().ok()?.duration_since(UNIX_EPOCH).ok()?.as_millis();
        Some(CacheKey { path: path.to_string_lossy().to_lowercase(), size: meta.len(), mtime_ms })
    }

    /// File stem on disk: FNV-1a 64 of the key (stable across runs and toolchains, unlike std's hasher).
    fn file_stem(&self) -> String {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for b in format!("{}|{}|{}", self.path, self.size, self.mtime_ms).bytes() {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
        format!("{h:016x}")
    }
}

/// Raw pixels from the OS: `size` x `size`, BGRA, premultiplied alpha, top row first.
pub struct Bgra {
    pub size: u32,
    pub pixels: Vec<u8>,
}

/// Premultiplied BGRA to straight RGBA, as PNG stores it.
pub fn unpremultiply(bgra: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bgra.len());
    for px in bgra.chunks_exact(4) {
        let (b, g, r, a) = (px[0], px[1], px[2], px[3]);
        let un = |c: u8| -> u8 {
            if a == 0 {
                0
            } else {
                ((u32::from(c) * 255 + u32::from(a) / 2) / u32::from(a)).min(255) as u8
            }
        };
        out.extend_from_slice(&[un(r), un(g), un(b), a]);
    }
    out
}

/// An RGBA image as PNG bytes.
pub fn encode_png(size: u32, rgba: &[u8]) -> Result<Vec<u8>, IconError> {
    let mut out = Vec::new();
    {
        let mut enc = png::Encoder::new(&mut out, size, size);
        enc.set_color(png::ColorType::Rgba);
        enc.set_depth(png::BitDepth::Eight);
        let mut w = enc.write_header()?;
        w.write_image_data(rgba)?;
        w.finish()?;
    }
    Ok(out)
}

/// The base64 alphabet (RFC 4648), for handing PNG bytes over the bridge as text.
pub fn base64(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for c in bytes.chunks(3) {
        let n = (u32::from(c[0]) << 16) | (u32::from(*c.get(1).unwrap_or(&0)) << 8) | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= c.len() {
                s.push(A[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                s.push('=');
            }
        }
    }
    s
}

/// Reads icons from the OS: the real one on Windows, a fake in tests.
pub type Extract = dyn Fn(&Path, u32) -> Option<Bgra> + Send + Sync;

/// The icon cache: memory first, then `dir`, then the OS.
pub struct IconStore {
    dir: PathBuf,
    mem: Mutex<HashMap<CacheKey, Option<AppIcon>>>,
    extract: Box<Extract>,
    extractions: AtomicUsize,
}

impl IconStore {
    pub fn new(dir: PathBuf, extract: Box<Extract>) -> IconStore {
        IconStore { dir, mem: Mutex::new(HashMap::new()), extract, extractions: AtomicUsize::new(0) }
    }

    /// The store the app uses: the shell's icons, cached under `<app data>/icons`.
    pub fn open_at(app_data: &Path) -> IconStore {
        IconStore::new(app_data.join("icons"), Box::new(os_extract))
    }

    /// How many times the OS was asked (a cache hit asks nothing).
    pub fn extractions(&self) -> usize {
        self.extractions.load(Ordering::Relaxed)
    }

    /// The icon of `exe`, or None when there is none to read (no such file, a
    /// path Windows hides, a file the shell has no icon for).
    pub fn icon(&self, exe: &Path) -> Result<Option<AppIcon>, IconError> {
        let Some(key) = CacheKey::of(exe) else { return Ok(None) };
        if let Some(hit) = self.lock().get(&key) {
            return Ok(hit.clone());
        }
        let found = match self.read_disk(&key) {
            Some(hit) => hit,
            None => {
                let made = self.make(exe)?;
                self.write_disk(&key, made.as_ref())?;
                made
            }
        };
        self.lock().insert(key, found.clone());
        Ok(found)
    }

    fn make(&self, exe: &Path) -> Result<Option<AppIcon>, IconError> {
        self.extractions.fetch_add(1, Ordering::Relaxed);
        let mut pngs = Vec::with_capacity(SIZES.len());
        for size in SIZES {
            let Some(img) = (self.extract)(exe, size) else { return Ok(None) };
            if img.size != size || img.pixels.len() != (size * size * 4) as usize {
                return Ok(None);
            }
            let rgba = unpremultiply(&img.pixels);
            // A fully transparent picture is no icon.
            if rgba.chunks_exact(4).all(|p| p[3] == 0) {
                return Ok(None);
            }
            pngs.push(base64(&encode_png(size, &rgba)?));
        }
        let mut it = pngs.into_iter();
        Ok(match (it.next(), it.next()) {
            (Some(x1), Some(x2)) => Some(AppIcon { x1, x2 }),
            _ => None,
        })
    }

    fn paths(&self, key: &CacheKey) -> (PathBuf, PathBuf, PathBuf) {
        let stem = key.file_stem();
        (self.dir.join(format!("{stem}-32.b64")), self.dir.join(format!("{stem}-64.b64")), self.dir.join(format!("{stem}.none")))
    }

    /// A disk hit: Some(Some(icon)), Some(None) for a cached "no icon", None for a miss.
    fn read_disk(&self, key: &CacheKey) -> Option<Option<AppIcon>> {
        let (p1, p2, none) = self.paths(key);
        if none.exists() {
            return Some(None);
        }
        let x1 = fs::read_to_string(p1).ok()?;
        let x2 = fs::read_to_string(p2).ok()?;
        (!x1.is_empty() && !x2.is_empty()).then_some(Some(AppIcon { x1, x2 }))
    }

    fn write_disk(&self, key: &CacheKey, icon: Option<&AppIcon>) -> Result<(), IconError> {
        fs::create_dir_all(&self.dir)?;
        let (p1, p2, none) = self.paths(key);
        match icon {
            Some(i) => {
                fs::write(p1, &i.x1)?;
                fs::write(p2, &i.x2)?;
            }
            None => fs::write(none, b"")?,
        }
        Ok(())
    }

    /// The cache holds plain data, so a poisoned lock is still usable.
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<CacheKey, Option<AppIcon>>> {
        match self.mem.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        }
    }
}

#[cfg(windows)]
fn os_extract(path: &Path, size: u32) -> Option<Bgra> {
    win::extract(path, size)
}

/// Off Windows there is no shell to ask.
#[cfg(not(windows))]
fn os_extract(_path: &Path, _size: u32) -> Option<Bgra> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(b64: &str) -> (png::OutputInfo, Vec<u8>) {
        // Test-side base64 decode, so the encoder is checked against an independent reading.
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut bits = Vec::new();
        for c in b64.bytes().filter(|&c| c != b'=') {
            let v = alphabet.iter().position(|&a| a == c).expect("base64 char") as u32;
            bits.push(v);
        }
        let mut bytes = Vec::new();
        for chunk in bits.chunks(4) {
            let mut n = 0u32;
            for (i, v) in chunk.iter().enumerate() {
                n |= v << (18 - 6 * i);
            }
            for i in 0..chunk.len().saturating_sub(1) {
                bytes.push((n >> (16 - 8 * i)) as u8);
            }
        }
        let dec = png::Decoder::new(std::io::Cursor::new(bytes));
        let mut reader = dec.read_info().expect("png header");
        let mut buf = vec![0; reader.output_buffer_size().expect("size")];
        let info = reader.next_frame(&mut buf).expect("png frame");
        buf.truncate(info.buffer_size());
        (info, buf)
    }

    fn fake(path: &Path, size: u32) -> Option<Bgra> {
        if path.to_string_lossy().contains("noicon") {
            return None;
        }
        // Half-transparent blue-ish square, premultiplied.
        let mut pixels = Vec::new();
        for _ in 0..size * size {
            pixels.extend_from_slice(&[100, 50, 25, 128]);
        }
        Some(Bgra { size, pixels })
    }

    #[test]
    fn unpremultiply_restores_straight_alpha() {
        assert_eq!(unpremultiply(&[100, 50, 25, 128]), vec![50, 100, 199, 128]);
        assert_eq!(unpremultiply(&[0, 0, 0, 0]), vec![0, 0, 0, 0]);
        assert_eq!(unpremultiply(&[255, 255, 255, 255]), vec![255, 255, 255, 255]);
    }

    #[test]
    fn base64_matches_rfc_4648() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn caches_in_memory_and_on_disk_by_path_size_and_mtime() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let exe = tmp.path().join("app.exe");
        fs::write(&exe, b"MZ fake").expect("write exe");
        let store = IconStore::new(tmp.path().join("icons"), Box::new(fake));
        let first = store.icon(&exe).expect("icon").expect("some icon");
        assert_eq!(store.extractions(), 1);
        let (info, rgba) = decode(&first.x1);
        assert_eq!((info.width, info.height), (32, 32));
        assert_eq!(&rgba[..4], &[50, 100, 199, 128]);
        assert_eq!(decode(&first.x2).0.width, 64);
        // Memory hit.
        assert_eq!(store.icon(&exe).expect("icon"), Some(first.clone()));
        assert_eq!(store.extractions(), 1);
        // Disk hit from a fresh store (a restart).
        let again = IconStore::new(tmp.path().join("icons"), Box::new(fake));
        assert_eq!(again.icon(&exe).expect("icon"), Some(first));
        assert_eq!(again.extractions(), 0);
        // A changed exe (new size) is a new key: asked again.
        fs::write(&exe, b"MZ fake, updated").expect("rewrite exe");
        store.icon(&exe).expect("icon");
        assert_eq!(store.extractions(), 2);
    }

    #[test]
    fn no_icon_is_none_and_cached_too() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let exe = tmp.path().join("noicon.exe");
        fs::write(&exe, b"MZ").expect("write exe");
        let store = IconStore::new(tmp.path().join("icons"), Box::new(fake));
        assert_eq!(store.icon(&exe).expect("icon"), None);
        assert_eq!(store.icon(&exe).expect("icon"), None);
        assert_eq!(store.extractions(), 1);
        // A path that does not exist never reaches the OS.
        assert_eq!(store.icon(Path::new(r"C:\no\such\dir\nothing.exe")).expect("icon"), None);
        assert_eq!(store.extractions(), 1);
    }

    /// The shell's own icon for a system exe: a real PNG at both sizes with real alpha,
    /// a cache hit on the second call, and None for a bogus path. Read only.
    #[cfg(windows)]
    #[test]
    fn extracts_notepad_icon_from_the_shell() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = IconStore::open_at(tmp.path());
        let notepad = Path::new(r"C:\Windows\System32\notepad.exe");
        assert!(notepad.exists(), "notepad.exe is part of Windows");
        let icon = store.icon(notepad).expect("icon").expect("notepad has an icon");
        for (b64, size) in [(&icon.x1, 32u32), (&icon.x2, 64u32)] {
            let (info, rgba) = decode(b64);
            assert_eq!((info.width, info.height), (size, size));
            assert_eq!(info.color_type, png::ColorType::Rgba);
            let alphas: Vec<u8> = rgba.chunks_exact(4).map(|p| p[3]).collect();
            assert!(alphas.iter().any(|&a| a > 0), "some pixels are drawn");
            assert!(alphas.iter().any(|&a| a < 255), "the icon has transparent parts, so alpha was kept");
        }
        assert_eq!(store.extractions(), 1);
        assert_eq!(store.icon(notepad).expect("icon"), Some(icon));
        assert_eq!(store.extractions(), 1, "second call is a cache hit");
        assert_eq!(store.icon(Path::new(r"C:\Windows\System32\no-such-sieve-test.exe")).expect("icon"), None);
    }
}
