# go-adb

Go ADB library.

- Full control over timeouts and cancellation.
- High-level idiomatic Go wrappers around common functionality.
- Access to low-level protocol details where required.
- All errors are checked.
- Focused on modern APIs; legacy ADB behaviour is not a priority.
- Highly extensible.

> [!WARNING]
> This library is a work-in-progress. Only parts of it have been fully tested, and the API is experimental and subject to change.

To keep this library maintainable and reduce the risk of breakage across versions, features not part of the core adb protocol are out of scope for this library. This includes interacting with on-device commands like am, pm, input, and so in, including through abb. These features could be implemented as part of another library if needed.
