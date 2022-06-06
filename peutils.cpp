#include "peutils.h"

static const UINT BLOCK_SIZE = 32;
static const UINT PATTERN_SIZE = 4;

const std::map<std::string, ULONG32> ParseSyscallNumbers()
{
	std::map<std::string, ULONG32> syscallNumbersMap;

	HMODULE hNtDll = ::GetModuleHandle(L"ntdll.dll");
	if (!hNtDll) {
		std::cerr << "[x] Unable to get the module handle" << std::endl;
		return syscallNumbersMap;
	}

	/*
	*	typedef struct _IMAGE_DOS_HEADER {
	*		WORD e_magic;		// Magic number
	*		...
	*		LONG e_lfanew;		// PE file header
	*	} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
	*	typedef struct _IMAGE_NT_HEADERS64 {
	*		DWORD Signature;
	*		...
	*	} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;
	*/

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hNtDll;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((LPBYTE)pDosHeader + pDosHeader->e_lfanew);

	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE || pNtHeader->Signature != IMAGE_NT_SIGNATURE) {
		std::cerr << "[x] This file contains invalid signatures" << std::endl;
		return syscallNumbersMap;
	}

	/*
	*	typedef struct _IMAGE_OPTIONAL_HEADER64 {
	*		...
	*		IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
	*	} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;
	*/

	PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)pDosHeader + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	if (!pExportDirectory) {
		std::cerr << "[x] Couldn't find the export directory of the PE file" << std::endl;
		return syscallNumbersMap;
	}

	/*
	*	typedef struct _IMAGE_EXPORT_DIRECTORY {
	*		...
	*		DWORD   AddressOfFunctions;     // RVA from base of image
	*		DWORD   AddressOfNames;         // RVA from base of image
	*		DWORD   AddressOfNameOrdinals;  // RVA from base of image
	*	} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
	*/

	PDWORD dwAddressOfFunctions = (PDWORD)((LPBYTE)pDosHeader + pExportDirectory->AddressOfFunctions);
	PDWORD dwAddressOfNames = (PDWORD)((LPBYTE)pDosHeader + pExportDirectory->AddressOfNames);
	PWORD dwAddressOfNameOrdinals = (PWORD)((LPBYTE)pDosHeader + pExportDirectory->AddressOfNameOrdinals);

	UCHAR pFunctionBlock[BLOCK_SIZE] = { 0 };
	CONST UCHAR bytePattern[PATTERN_SIZE] = { 0x4C, 0x8B, 0xD1, 0xB8 }; // mov r10, rcx 

	for (DWORD i = 0; i < pExportDirectory->NumberOfFunctions; ++i) {
		::RtlZeroMemory(&pFunctionBlock, BLOCK_SIZE);

		PVOID pAddressOfFunction = (PVOID)((LPBYTE)pDosHeader + dwAddressOfFunctions[dwAddressOfNameOrdinals[i]]);
		LPCCH pFunctionName = (LPCCH)pDosHeader + dwAddressOfNames[i];

		::RtlCopyMemory(&pFunctionBlock, pAddressOfFunction, BLOCK_SIZE);
		if (!pAddressOfFunction || !pFunctionName) {
			break;
		}

		for (int j = 0; j < BLOCK_SIZE; ++j) {
			if (pFunctionBlock[j] != bytePattern[j]) {
				break;
			}
			if (j == PATTERN_SIZE - 1) {
				// According to j00ru.vexillium.org, all the syscall numbers fit in 16 bits
				syscallNumbersMap[std::string(pFunctionName)] = (pFunctionBlock[5] << 8) | (pFunctionBlock[4]);
			}
		}
	}

	return syscallNumbersMap;
}