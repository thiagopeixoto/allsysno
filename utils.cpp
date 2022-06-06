#include "utils.h"

VOID NTAPI RtlInitUnicodeString(
    IN OUT PUNICODE_STRING DestinationString,
    IN PCWSTR SourceString
)
{
    SIZE_T Size;
    CONST SIZE_T MaxSize = (MAXUSHORT & ~1) - sizeof(UNICODE_NULL);

    if (SourceString)
    {
        Size = wcslen(SourceString) * sizeof(WCHAR);
        __analysis_assume(Size <= MaxSize);

        if (Size > MaxSize)
            Size = MaxSize;
        DestinationString->Length = (USHORT)Size;
        DestinationString->MaximumLength = (USHORT)Size + sizeof(UNICODE_NULL);
    }
    else
    {
        DestinationString->Length = 0;
        DestinationString->MaximumLength = 0;
    }

    DestinationString->Buffer = (PWCHAR)SourceString;
}