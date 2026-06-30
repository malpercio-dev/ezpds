fn main() {
    tauri_plugin::Builder::new(&["start"])
        .android_path("android")
        .build();
}
