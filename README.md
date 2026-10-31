# Guardian

> [!WARNING]
> This is a passion project built and maintained with AI.

A Paper plugin and Fabric mod that check for prohibited client mods before players enter the server.

Requires Minecraft 26.3, Java 25, Fabric Loader 0.19.5+ and Fabric API.

## Setup

1. Put `guardian-paper-1.0.2.jar` in the server's `plugins` folder.
2. Install `guardian-client-1.0.2.jar` and Fabric API on each client.
3. Restart the server. Edit `plugins/Guardian/config.yml` to change the rules.

Clients without Guardian, with blocked mods, or with a failed scan are disconnected. Rules cover mod IDs, filenames, class paths and optional file hashes, including nested JARs.

Original [Freecam](https://modrinth.com/mod/freecam) is blocked; [LegacyFreecam](https://modrinth.com/plugin/legacyfreecam) is allowed. Existing installations should copy the new rules from [config.yml](src/main/resources/config.yml) into their server configuration.

When upgrading to 1.0.2, replace both JARs and restart Minecraft and the server. Missing clients time out after five seconds; scans have a separate timeout.

## Build

```sh
mvn clean verify
cd client
./gradlew clean build
```

Use `gradlew.bat` on Windows. The plugin is in `target/`; the mod is in `client/build/libs/`.

Open this folder in IntelliJ IDEA. The server uses Maven and the client uses Gradle. Use JDK 25 for both.

## Limits

Client reports can be forged; Guardian cannot replace server-side anti-cheat. Mods are checked on connection. Active resource packs are checked on connection and after reloads for hidden or mostly transparent terrain. Pack names are ignored; unused packs are not scanned. Custom terrain models can trigger false positives. Reports include loaded mod IDs and matched mod/resource rules, but no file contents or absolute paths. Tested with local Paper protocol connections; a full Fabric game-client test is still needed.

[MIT license](LICENSE).
