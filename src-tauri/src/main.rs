// Windows GUI subsystem, so no console window appears at launch — not even in
// debug builds. Dev-time tracing still reaches the terminal that ran
// `pnpm dev`, because the Tauri CLI forwards the child's stderr; release
// builds write to the rolling file sink instead (see `lib.rs::init_tracing`).
#![windows_subsystem = "windows"]

fn main() {
    ppxray_lib::run()
}
