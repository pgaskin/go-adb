# go-adb

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
