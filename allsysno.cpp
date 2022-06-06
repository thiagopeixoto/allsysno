#include <iostream>
#include "allsysno.h"

int main(int argc, const char *argv[])
{
    auto syscallNumbers = ParseSyscallNumbers();

    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING file;
    NTSTATUS status;
    const WCHAR* filename = L"\\??\\T:\\HelloWorld.txt";
    HANDLE hFile;
    IO_STATUS_BLOCK  IoStatusBlock;

    RtlInitUnicodeString(&file, filename);
    InitializeObjectAttributes(&ObjectAttributes, &file, OBJ_CASE_INSENSITIVE, 0, NULL);

    currentSyscallNumber = syscallNumbers["NtCreateFile"];
    auto NtCreateFile = (_NtCreateFile)&SyscallDispatcher;
    status = NtCreateFile(&hFile,
        FILE_GENERIC_WRITE,
        &ObjectAttributes,
        &IoStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_WRITE,
        FILE_OPEN_IF,
        FILE_RANDOM_ACCESS | FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );

    if (status != 0) {
        printf("Error status: 0x%X\n", status);
        return 1;
    }

    currentSyscallNumber = syscallNumbers["NtClose"];
    auto NtClose = (_NtClose)&SyscallDispatcher;
    status = NtClose(hFile);
    if (status != 0) {
        printf("Error status: 0x%X\n", status);
        return 1;
    }

    return 0;
}
