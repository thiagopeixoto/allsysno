# AllSysNo

This tool reads NTDLL.DLL from memory, parses the syscall numbers and helps in making direct syscalls, in order to help evasion. Unlike [SysWhispers2], it doesn't generate the syscall stubs and headers at compile time. In consequence, unfortunately, you have to set a syscall number global variable and cast the syscall dispatcher to the chosen NT function type every single time you want to invoke it. Although it looks very inconvenient (and it really is), I thought it could help to prevent some fingerprint. I could fix this inconvenience allocating W+X memory for each syscall stub before invoking them, but it could be too noisy. If you think about a possible and less-noisy solution, please let me know. :)

It is based on [SysWhispers2] and [Understanding Windows SysCalls - SysCall Dumper], but after noticing this latter seems to consider only one byte of the syscall number, I decided to fix it and share it.

## License

MIT

[SysWhispers2]: https://github.com/jthuraisamy/SysWhispers2
[Understanding Windows SysCalls - SysCall Dumper]: <https://guidedhacking.com/threads/understanding-windows-syscalls-syscall-dumper.14470/>