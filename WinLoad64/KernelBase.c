#include "pch.h"
#include "ntdll.h"
#include "kernelbase.h"

INT64 __fastcall BaseSetLastNtError(NTSTATUS status)
{
	const ULONG DosError = RtlNtStatusToDosError(status);
	RtlSetLastWin32Error(DosError);
	return DosError;
}

// LoadLibraryA/LoadLibraryExA/LoadLibraryW call LoadLibraryExW
// All exported from KernelBase.dll, imported by programs from kernel32.dll forwarder

HMODULE WINAPI __LoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{	
	if (!lpLibFileName || hFile || dwFlags & LOAD_LIBRARY_INVALID_BITS 
		|| dwFlags & LOAD_LIBRARY_DATAFILE_BOTH == LOAD_LIBRARY_DATAFILE_BOTH)
	{
		goto InvalidArgument;
	}

	UNICODE_STRING UnicodeLib;
	RtlInitUnicodeString(&UnicodeLib, lpLibFileName);
	USHORT len = UnicodeLib.Length;
	if (!len)
	{
		// Im not calling RtlInitUnicodeStringEx so I dont have to set BaseSetLastNtError, but real func does
		return 0;
	}

	// erasing trailing spaces from lib name
	do
	{
		// ntdll ofc uses bit shifting rather than dividing by sizeof(wchar)
		if (UnicodeLib.Buffer[(len / sizeof(wchar_t)) - 1] != ' ') 
		{
			break;
		}

		len -= 2;
		UnicodeLib.Length = len;

	} while (len);

	if (!len)
	{
	InvalidArgument:

		BaseSetLastNtError(STATUS_INVALID_PARAMETER);
		return 0;
	}

	NTSTATUS status;
	HMODULE hModule = NULL;

	if (dwFlags & (LOAD_LIBRARY_AS_DATAFILE | LOAD_WITH_ALTERED_SEARCH_PATH | LOAD_IGNORE_CODE_AUTHZ_LEVEL | LOAD_LIBRARY_AS_IMAGE_RESOURCE | LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE))
	{

	}
	else
	{

	}
}