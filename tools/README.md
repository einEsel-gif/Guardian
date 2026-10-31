# Local protocol test

`GuardianWireProbe.java` is an offline, localhost-only protocol client for Minecraft 26.3 (protocol 777). It never connects to a public server or executes mod code.

Start a disposable Paper 26.3 server on `127.0.0.1:25579` with Guardian 1.0.2, `online-mode=false` and `white-list=false`. Keep the normal five-second handshake timeout. Do not change these settings on a production server.

Run `java --class-path <path-to-gson.jar> tools/GuardianWireProbe.java` from this project. Gson is available in Maven's local dependency cache after building the plugin.

The probe checks clean and delayed handshakes, LegacyFreecam admission, blocked Freecam, old clients, missing clients, registration without readiness, required resource checks, Xray findings, and an Xray update after world entry. It stops at the server's finish-configuration packet; it is not a replacement for launching a real Fabric game client.
