//! The shell's icon for a file, as raw pixels. Read only, no admin.

use std::ffi::c_void;
use std::path::Path;

use windows::Win32::Foundation::SIZE;
use windows::Win32::Graphics::Gdi::{
    BI_RGB, BITMAP, BITMAPINFO, BITMAPINFOHEADER, CreateCompatibleDC, DIB_RGB_COLORS, DeleteDC, DeleteObject, GetDIBits, GetObjectW, HBITMAP,
};
use windows::Win32::System::Com::{COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoInitializeEx, CoUninitialize};
use windows::Win32::UI::Shell::{IShellItemImageFactory, SHCreateItemFromParsingName, SIIGBF_ICONONLY};
use windows::core::{HSTRING, PCWSTR};

use super::Bgra;

/// COM for the calling thread, for as long as this guard lives. The shell
/// item APIs need it; spawn_blocking threads have none of their own.
struct Com {
    owned: bool,
}

impl Com {
    fn init() -> Com {
        // SAFETY: plain call. S_OK and S_FALSE both need a matching CoUninitialize;
        // a thread already in another mode (RPC_E_CHANGED_MODE) is used as it is.
        let hr = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) };
        Com { owned: hr.is_ok() }
    }
}

impl Drop for Com {
    fn drop(&mut self) {
        if self.owned {
            // SAFETY: matches the successful CoInitializeEx above, on the same thread.
            unsafe { CoUninitialize() };
        }
    }
}

/// The icon Explorer shows for `path`, `size` x `size`, as premultiplied BGRA,
/// top row first. None when the shell has none (no such file, access denied).
pub fn extract(path: &Path, size: u32) -> Option<Bgra> {
    let _com = Com::init();
    let wide = HSTRING::from(path.as_os_str());
    // SAFETY: `wide` is a NUL-terminated UTF-16 path that outlives the call.
    let factory: IShellItemImageFactory = unsafe { SHCreateItemFromParsingName(PCWSTR(wide.as_ptr()), None) }.ok()?;
    let side = i32::try_from(size).ok()?;
    // SAFETY: plain COM call; the bitmap it returns is ours and deleted below.
    let hbm = unsafe { factory.GetImage(SIZE { cx: side, cy: side }, SIIGBF_ICONONLY) }.ok()?;
    let out = read_bitmap(hbm, size);
    // SAFETY: `hbm` came from GetImage and is deleted once.
    let _ = unsafe { DeleteObject(hbm.into()) };
    out
}

/// The bitmap's pixels as 32 bpp top-down BGRA, scaled by nothing: the shell
/// is asked for exactly `size` and anything else is refused.
fn read_bitmap(hbm: HBITMAP, size: u32) -> Option<Bgra> {
    let mut bm = BITMAP::default();
    // SAFETY: `bm` is a writable BITMAP of the size passed.
    let got = unsafe { GetObjectW(hbm.into(), std::mem::size_of::<BITMAP>() as i32, Some((&mut bm as *mut BITMAP).cast::<c_void>())) };
    if got == 0 || bm.bmWidth != size as i32 || bm.bmHeight.unsigned_abs() != size {
        return None;
    }
    let mut info = BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: size as i32,
            // Negative height: top-down rows.
            biHeight: -(size as i32),
            biPlanes: 1,
            biBitCount: 32,
            biCompression: BI_RGB.0,
            ..Default::default()
        },
        ..Default::default()
    };
    let mut pixels = vec![0u8; (size * size * 4) as usize];
    // SAFETY: plain call; the DC is deleted below.
    let dc = unsafe { CreateCompatibleDC(None) };
    if dc.is_invalid() {
        return None;
    }
    // SAFETY: `pixels` holds size * size 32 bpp pixels, exactly what `info` asks for.
    let lines = unsafe { GetDIBits(dc, hbm, 0, size, Some(pixels.as_mut_ptr().cast::<c_void>()), &mut info, DIB_RGB_COLORS) };
    // SAFETY: `dc` came from CreateCompatibleDC and is deleted once.
    let _ = unsafe { DeleteDC(dc) };
    (lines == size as i32).then_some(Bgra { size, pixels })
}
