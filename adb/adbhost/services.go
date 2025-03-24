package adbhost

// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/services.cpp;drc=01cbbf505e3348a70cd846b26fae603bdf44b3c5
// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/adb.cpp;l=1275-1616;drc=9f298fb1f3317371b49439efb20a598b3a881bf3
// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/adb.cpp;l=1133-1242;drc=9c843a66d11d85e1f69e944f1b37314d3e47aab1

// host request
// TODO: kill
// TODO: server-status
// TODO: devices, devices-l
// TODO: reconnect-offline
// TODO: host-features
// TODO: disconnect
// TODO: version
// TODO: emulator

// host socket
// TODO: track-devices (short, long, proto-binary, proto-text)
// TODO: connect
// TODO: pair

// host transport
// TODO: features
// TODO: disconnect
// TODO: get-serialno
// TODO: get-devpath
// TODO: get-state
// TODO: reconnect
// TODO: attach
// TODO: detach
// TODO: list-forward
// TODO: forward
// TODO: killforward
// TODO: mdns:check
// TODO: mdns:services

// note: reverse works by updating a whitelist on the host, and the device opens tcp:... services in reverse
