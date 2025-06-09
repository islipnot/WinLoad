#include "pch.h"
#include "ntdll.h"

DATA_TABLE_ENTRY* LdrpHandleReplacedModule(const DATA_TABLE_ENTRY* ReplacedModule)
{
	const DATA_TABLE_ENTRY* result = ReplacedModule;

	if (result)
	{
		LOAD_CONTEXT* ReplacedContext = result->LoadContext;

		if (ReplacedContext && !(ReplacedContext->Flags & Unknown5) && ReplacedContext->LdrEntry != ReplacedModule)
		{
			result = ReplacedContext->LdrEntry;
			ReplacedContext->LdrEntry = ReplacedModule;
		}
	}

	return result;
}

PWSTR RtlGetNtSystemRoot()
{
	PWSTR SharedData = *(PWSTR*)NtCurrentPeb()->SharedData;
	if (SharedData && *SharedData) return SharedData + PebSystemRootOffset;
	else return (PWSTR)SystemRootAddress;
}

ULONG LdrpComputeTlsSizeAndAlignment(TLS_ENTRY* TlsEntry, ULONG* pTlsAlignment)
{
	const IMAGE_TLS_DIRECTORY32* TlsDirectory = &TlsEntry->TlsDirectory;
	ULONG AlignmentBits = ((DWORD)TlsDirectory->Alignment >> 20) & 0xF;
	
	if ((DWORD)TlsDirectory->Alignment & 0xF00000)
	{
		AlignmentBits -= 1;
	}

	const ULONG AlignmentValueBit = 1 << AlignmentBits;
	ULONG TlsAlignment = 8;

	if (AlignmentValueBit > 8)
	{
		TlsAlignment = AlignmentValueBit;
	}

	*pTlsAlignment = TlsAlignment - 1;

	return TlsDirectory->EndAddressOfRawData - TlsDirectory->StartAddressOfRawData;
}