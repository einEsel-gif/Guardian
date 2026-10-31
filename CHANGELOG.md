# Changelog

## 1.0.2

- Detect common Xray resource packs by inspecting active terrain models and texture transparency.
- Recheck resource packs after joining and resource reloads; disconnect when prohibited changes are found.
- Require the resource-pack check in client reports. Update both JARs.

## 1.0.1

- Fix channel registration when connecting Fabric clients to Paper.
- Wait for client readiness before sending the challenge; reject missing clients after five seconds.
- Add client logs and distinct handshake/scan timeout messages.
- Update both the plugin and client mod.

## 1.0.0

- Standalone Paper plugin and required Fabric mod for Minecraft 26.3.
- Checks mod IDs, archives, class paths and optional hashes before world entry.
- Configurable rules, English messages and automated tests.
