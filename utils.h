#pragma once

#include <Windows.h>
#include "syscalls.h"

#define MAXUSHORT USHRT_MAX

#define OBJ_CASE_INSENSITIVE 0x00000040
#define FILE_OPEN_IF 0x00000003
#define FILE_DIRECTORY_FILE 0x00000001
#define FILE_RANDOM_ACCESS 0x00000800
#define FILE_NON_DIRECTORY_FILE 0x00000040
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020


VOID NTAPI RtlInitUnicodeString(
    IN OUT PUNICODE_STRING DestinationString,
    IN PCWSTR SourceString
);