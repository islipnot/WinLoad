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