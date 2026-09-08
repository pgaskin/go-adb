# go-adb

[![Go Reference](https://pkg.go.dev/badge/github.com/pgaskin/go-adb.svg)](https://pkg.go.dev/github.com/pgaskin/go-adb)

Go ADB library.

- Full control over timeouts and cancellation.
- High-level idiomatic Go wrappers around common functionality.
- Access to low-level protocol details where required.
- All errors are checked.
- Focused on modern APIs; legacy ADB behaviour is not a priority.
- Highly extensible.
- Robust `os/exec`-style wrapper for shell commands with streaming, exit code support, split stderr/stdout, pty support, and error handling.
- Support for exposing an existing device as an `adb connect`able target.
- Completely hand-written and carefully designed (no AI involvement at all).

> [!WARNING]
> This library is a work-in-progress. The API is experimental and subject to change, and some features are missing. However, the functionality which has been implemented is stable and I'm using it heavily in other projects.

To keep this library maintainable and reduce the risk of breakage across versions, features not part of the core adb protocol are out of scope for this library. This includes interacting with on-device commands like am, pm, input, and so in, including through abb. These features could be implemented as part of another library if needed.

The [`adb`](./adb/) package contains thin idiomatic Go wrappers around core ADB functionality, with the [`adb/adbproto`](./adb/adbproto/) package implementing low-level ADB protocol primitives (based on how the Android works).

The [`adblib`](./adblib/) package implements opionated high-level wrappers around ADB functionality resembling the API of the corresponding Go stdlib packages (e.g., [`adblib/adbnet`](./adblib/adbnet/) for `net`, [`adblib/adbexec/v2`](./adblib/adbexec/v2/) for `os/exec`, [`adblib/adbsync`](./adblib/adbsync/) for `os`), plus unique functionality like [`adblib/adbproxy`](./adblib/adbproxy/).

The [`examples`](./examples/) folder contains some working examples using go-adb, but is still relatively incomplete.
