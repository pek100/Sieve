//! Reading a small settings file that a person may have written from an admin
//! prompt. The caller names the file in its own report.

use std::io::Read;
use std::path::Path;

/// The file's bytes, at most `max` of them. `None` when there is no file; a
/// larger file is refused without reading the rest of it.
pub fn read_capped(path: &Path, max: u64) -> Result<Option<Vec<u8>>, String> {
    let read = std::fs::File::open(path).and_then(|f| {
        let mut bytes = Vec::new();
        f.take(max + 1).read_to_end(&mut bytes).map(|_| bytes)
    });
    match read {
        Ok(bytes) if bytes.len() as u64 > max => Err(format!("larger than {max} bytes")),
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

/// The bytes after any encoding mark. Windows PowerShell writes UTF-8 with a
/// BOM, and UTF-16 with `>`. A BOM is not content; UTF-16 is refused by name so
/// the cause is visible.
pub fn content(bytes: &[u8]) -> Result<&[u8], String> {
    if bytes.starts_with(&[0xFF, 0xFE]) || bytes.starts_with(&[0xFE, 0xFF]) {
        return Err("UTF-16; save it as UTF-8".into());
    }
    Ok(bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_utf8_bom_is_not_content_and_either_utf16_is_refused_by_name() {
        assert_eq!(content(b"{}").unwrap(), b"{}");
        assert_eq!(content(b"\xEF\xBB\xBF{}").unwrap(), b"{}");
        for mark in [[0xFF, 0xFE], [0xFE, 0xFF]] {
            assert!(content(&[mark[0], mark[1], b'{', 0]).unwrap_err().contains("UTF-16"));
        }
    }

    #[test]
    fn the_cap_admits_exactly_its_size_and_no_file_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.json");
        assert_eq!(read_capped(&path, 4), Ok(None));
        std::fs::write(&path, b"1234").unwrap();
        assert_eq!(read_capped(&path, 4).unwrap().as_deref(), Some(&b"1234"[..]));
        std::fs::write(&path, b"12345").unwrap();
        assert!(read_capped(&path, 4).unwrap_err().contains("larger than 4 bytes"));
    }

    #[test]
    fn a_path_that_cannot_be_read_gives_its_reason() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!read_capped(dir.path(), 4).unwrap_err().is_empty(), "a directory is not a file");
    }
}
