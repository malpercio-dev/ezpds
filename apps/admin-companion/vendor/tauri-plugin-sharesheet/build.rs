// Copyright 2019-2023 Tauri Programme within The Commons Conservancy
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

const COMMANDS: &[&str] = &["share_text"];

fn main() {
    tauri_plugin::Builder::new(COMMANDS)
        .global_api_script_path("./api-iife.js")
        .android_path("android")
        .ios_path("ios")
        .build();

    // VENDORED MODIFICATION (see VENDORED.md): the upstream build.rs injected the
    // `com.apple.developer.group-session` (Group Activities / SharePlay) entitlement into the
    // consuming app's iOS entitlements here. The Share Pane (`UIActivityViewController`) does
    // not use SharePlay, so declaring it forced the App Store provisioning profile to carry an
    // unused capability and failed `exportArchive`. Removed — `share_text` is unaffected.
}
