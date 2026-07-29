#!/usr/bin/env python3
"""Answer the one question tauri's signing step asks of a pbxproj.

`cargo tauri ios build` writes CODE_SIGN_IDENTITY / DEVELOPMENT_TEAM /
PROVISIONING_PROFILE_SPECIFIER, and the whole `provisioningProfiles` + `signingStyle`
half of its generated ExportOptions, only if its own line-oriented parser can find the
`_iOS` target's release build configuration. If it cannot, tauri does not warn: it
silently falls back to automatic signing, stamps a self-signed "Apple Distribution:
Tauri (unset)" placeholder, and the build fails minutes later at the export with a
message about a missing "iOS Distribution" certificate that names none of this.

That parser derails on a pbxproj tauri has already stamped, because it inserts settings
at recorded line numbers which go stale as earlier insertions shift the file. One local
`cargo tauri ios build` is enough to leave build settings sitting after a closing brace —
or after `/* End XCBuildConfiguration section */` entirely. Xcode and `plutil -lint` both
accept the result, so nothing else in the toolchain notices.

This is a faithful port of that parser's state machine (crates/tauri-cli/src/helpers/
pbxproj.rs at the pinned version). Exit 0 if tauri would find the configuration.
"""
import sys


def split_at_indentation(s):
    for i, c in enumerate(s):
        if not c.isspace():
            return s[:i], s[i:]
    return None


def parse(path):
    lines = open(path, encoding="utf-8").read().split("\n")
    build_configurations, configuration_lists = {}, {}
    state, current = "Idle", None
    positions = iter(range(len(lines)))

    for index in positions:
        line = lines[index]
        if state == "Idle":
            if line == "/* Begin XCBuildConfiguration section */":
                state = "BuildConfiguration"
            elif line == "/* Begin XCConfigurationList section */":
                state = "ConfigurationList"

        elif state == "BuildConfiguration":
            if line == "/* End XCBuildConfiguration section */":
                state = "Idle"
            elif (split := split_at_indentation(line)) and split[1].split():
                current = split[1].split()[0]
                build_configurations[current] = True
                state = "BuildConfigurationObject"

        elif state == "BuildConfigurationObject":
            if "buildSettings" in line:
                state = "BuildSettings"
            elif (split := split_at_indentation(line)) and split[1] == "};":
                state = "BuildConfiguration"

        elif state == "BuildSettings":
            if split := split_at_indentation(line):
                if split[1] == "};":
                    state = "BuildConfigurationObject"
                elif " = " in split[1].rstrip(";"):
                    _, value = split[1].rstrip(";").split(" = ", 1)
                    if value == "(":  # multi-line list value
                        for inner in positions:
                            nested = split_at_indentation(lines[inner])
                            if nested and nested[1] == ");":
                                break

        elif state == "ConfigurationList":
            if line == "/* End XCConfigurationList section */":
                state = "Idle"
            elif (split := split_at_indentation(line)) and " " in split[1]:
                identifier, comment = split[1].split(" ", 1)
                configuration_lists[identifier] = {
                    "comment": comment[:-4] if comment.endswith(" = {") else comment,
                    "refs": [],
                }
                current = identifier
                state = "ConfigurationListObject"

        elif state == "ConfigurationListObject":
            if "buildConfigurations" in line:
                state = "ConfigurationListRefs"
            elif (split := split_at_indentation(line)) and split[1] == "};":
                state = "ConfigurationList"

        elif state == "ConfigurationListRefs":
            if split := split_at_indentation(line):
                if split[1] == ");":
                    state = "ConfigurationListObject"
                elif " " in split[1]:
                    ref, comment = split[1].split(" ", 1)
                    configuration_lists[current]["refs"].append((ref, comment.rstrip(",")))

    return build_configurations, configuration_lists


def main():
    path = sys.argv[1]
    # `release`, matching what `just ios-ipa` builds; a --debug build would look for `debug`.
    build_configurations, configuration_lists = parse(path)

    target = next(
        (v for v in configuration_lists.values() if "_iOS" in v["comment"]), None
    )
    if target is None:
        print(
            "✗ tauri's parser finds no _iOS build-configuration list in this pbxproj.\n"
            "  It would silently skip every signing setting and fall back to automatic\n"
            "  signing, failing at the export with a misleading certificate error.\n"
            f"  ({len(configuration_lists)} configuration lists parsed, "
            f"{len(build_configurations)} build configurations)",
            file=sys.stderr,
        )
        return 1

    for ref, comment in target["refs"]:
        if "release" in comment and ref in build_configurations:
            return 0

    print(
        "✗ tauri's parser finds the _iOS list but not its `release` build configuration,\n"
        "  so it would skip every signing setting and fall back to automatic signing.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
