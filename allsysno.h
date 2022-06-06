#pragma once

#include "peutils.h"
#include "syscalls.h"
#include "utils.h"

EXTERN_C DWORD currentSyscallNumber;
EXTERN_C PVOID SyscallDispatcher;