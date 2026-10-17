//! The tray icon (plan row 74). It holds no sampling logic of its own:
//! Pause and Resume are sent to the window as a `tray-action` event and the
//! window runs the same poller actions its own pause pill uses. Quit is
//! Rust's, except while Sieve's DNS backup exists: then the window asks
//! first (restore DNS and quit, keep filtering, cancel). The window
//! reports its phase back through `tray_set_state`, which sets the tooltip,
//! which menu items are enabled, and a dimmed icon while not live.

use serde::{Deserialize, Serialize};
use tauri::image::Image;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, Runtime};

pub const TRAY_ID: &str = "sieve";
/// Event the window listens to (see src/data/desktop.ts).
pub const TRAY_EVENT: &str = "tray-action";
/// Minutes the tray's Pause item pauses for.
pub const TRAY_PAUSE_MINUTES: u32 = 5;

/// What a menu item asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TrayAction {
    Pause { minutes: u32 },
    Resume,
    Open,
    Quit,
}

/// Menu item ids, one per action. The id is the action's wire name.
pub const MENU: [(&str, &str); 4] = [("pause", "Pause 5 min"), ("resume", "Resume"), ("open", "Open Sieve"), ("quit", "Quit")];

pub fn action_for(id: &str) -> Option<TrayAction> {
    match id {
        "pause" => Some(TrayAction::Pause { minutes: TRAY_PAUSE_MINUTES }),
        "resume" => Some(TrayAction::Resume),
        "open" => Some(TrayAction::Open),
        "quit" => Some(TrayAction::Quit),
        _ => None,
    }
}

/// What the window says about itself; derived on the TypeScript side (src/core/tray.ts).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrayState {
    pub tooltip: String,
    pub can_pause: bool,
    pub can_resume: bool,
    /// Draw the icon faded: sampling is not live.
    pub dim: bool,
}

/// The icon at reduced opacity: every alpha byte (RGBA) scaled to 45 %.
pub fn dimmed_rgba(rgba: &[u8]) -> Vec<u8> {
    rgba.chunks(4)
        .flat_map(|px| match px {
            [r, g, b, a] => [*r, *g, *b, (u16::from(*a) * 45 / 100) as u8],
            _ => [0, 0, 0, 0],
        })
        .collect()
}

/// Handles the window-state command needs, kept in managed state.
pub struct TrayItems<R: Runtime> {
    pause: MenuItem<R>,
    resume: MenuItem<R>,
    icon: Option<Image<'static>>,
    dim_icon: Option<Image<'static>>,
}

fn show_main<R: Runtime>(app: &AppHandle<R>) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
    }
}

/// Who handles Quit: Rust quits at once, unless Sieve's DNS backup exists
/// (Windows may be pointed at Sieve, and quitting would leave it asking a
/// server that is gone), in which case the window asks the user first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuitRoute {
    Now,
    AskInWindow,
}

pub fn quit_route(dns_backup_exists: bool) -> QuitRoute {
    if dns_backup_exists { QuitRoute::AskInWindow } else { QuitRoute::Now }
}

fn emit<R: Runtime>(app: &AppHandle<R>, action: TrayAction) -> bool {
    match app.emit(TRAY_EVENT, action) {
        Ok(()) => true,
        Err(e) => {
            eprintln!("tray: could not reach the window: {e}");
            false
        }
    }
}

fn run<R: Runtime>(app: &AppHandle<R>, action: TrayAction) {
    match action {
        TrayAction::Open => show_main(app),
        TrayAction::Quit => {
            let backup = app
                .path()
                .app_data_dir()
                .is_ok_and(|d| crate::sysdns::backup::exists(&crate::sysdns::backup::dir_in(&d)));
            match quit_route(backup) {
                QuitRoute::Now => app.exit(0),
                QuitRoute::AskInWindow => {
                    show_main(app);
                    // No window to ask: quitting is still the user's order.
                    if !emit(app, action) {
                        app.exit(0);
                    }
                }
            }
        }
        TrayAction::Pause { .. } | TrayAction::Resume => {
            emit(app, action);
        }
    }
}

pub fn install<R: Runtime>(app: &tauri::App<R>) -> tauri::Result<()> {
    let item = |(id, label): (&str, &str), enabled: bool| MenuItem::with_id(app, id, label, enabled, None::<&str>);
    let pause = item(MENU[0], true)?;
    let resume = item(MENU[1], false)?;
    let open = item(MENU[2], true)?;
    let quit = item(MENU[3], true)?;
    let sep = PredefinedMenuItem::separator(app)?;
    let menu = Menu::with_items(app, &[&pause, &resume, &sep, &open, &quit])?;

    let icon = app.default_window_icon().map(|i| i.clone().to_owned());
    let dim_icon = icon.as_ref().map(|i| Image::new_owned(dimmed_rgba(i.rgba()), i.width(), i.height()));

    let mut builder = TrayIconBuilder::with_id(TRAY_ID)
        .tooltip("Sieve")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| {
            if let Some(action) = action_for(event.id().as_ref()) {
                run(app, action);
            }
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = event {
                show_main(tray.app_handle());
            }
        });
    if let Some(i) = icon.clone() {
        builder = builder.icon(i);
    }
    builder.build(app)?;
    app.manage(TrayItems { pause, resume, icon, dim_icon });
    Ok(())
}

/// Apply the window's state to the tray.
pub fn apply<R: Runtime>(app: &AppHandle<R>, state: &TrayState) -> Result<(), String> {
    let tray = app.tray_by_id(TRAY_ID).ok_or("tray is not installed")?;
    let items = app.try_state::<TrayItems<R>>().ok_or("tray items are not installed")?;
    tray.set_tooltip(Some(&state.tooltip)).map_err(|e| e.to_string())?;
    items.pause.set_enabled(state.can_pause).map_err(|e| e.to_string())?;
    items.resume.set_enabled(state.can_resume).map_err(|e| e.to_string())?;
    let icon = if state.dim { items.dim_icon.clone() } else { items.icon.clone() };
    if icon.is_some() {
        tray.set_icon(icon).map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_menu_id_maps_to_its_action() {
        let actions: Vec<_> = MENU.iter().map(|(id, _)| action_for(id)).collect();
        assert_eq!(
            actions,
            vec![
                Some(TrayAction::Pause { minutes: 5 }),
                Some(TrayAction::Resume),
                Some(TrayAction::Open),
                Some(TrayAction::Quit)
            ]
        );
        assert_eq!(action_for("nope"), None);
    }

    #[test]
    fn actions_cross_to_the_window_as_tagged_json() {
        let v = serde_json::to_value(TrayAction::Pause { minutes: 5 }).expect("serialises");
        assert_eq!(v, serde_json::json!({ "kind": "pause", "minutes": 5 }));
        assert_eq!(serde_json::to_value(TrayAction::Resume).expect("serialises"), serde_json::json!({ "kind": "resume" }));
    }

    #[test]
    fn tray_state_reads_the_camel_case_the_window_sends() {
        let s: TrayState =
            serde_json::from_value(serde_json::json!({ "tooltip": "Sieve: live", "canPause": true, "canResume": false, "dim": false }))
                .expect("parses");
        assert!(s.can_pause && !s.can_resume && !s.dim);
    }

    #[test]
    fn quit_asks_in_the_window_only_while_a_dns_backup_exists() {
        assert_eq!(quit_route(false), QuitRoute::Now);
        assert_eq!(quit_route(true), QuitRoute::AskInWindow);
        assert_eq!(serde_json::to_value(TrayAction::Quit).expect("serialises"), serde_json::json!({ "kind": "quit" }));
    }

    #[test]
    fn dimming_scales_only_alpha() {
        assert_eq!(dimmed_rgba(&[10, 20, 30, 200, 1, 2, 3, 0]), vec![10, 20, 30, 90, 1, 2, 3, 0]);
    }
}
