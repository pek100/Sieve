fn main() {
  // The Windows icon resource is compiled when this script runs. Without this
  // line a build profile whose script last ran before an icon change keeps
  // embedding the old icon (seen 2026-10-17: `tauri dev` showed the old mark).
  println!("cargo:rerun-if-changed=icons");
  tauri_build::build()
}
