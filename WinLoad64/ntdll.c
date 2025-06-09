#include "pch.h"
#include "ntdll.h"

INT64 __fastcall RtlSetLastWin32Error(UINT error)
{
	TEB* teb = NtCurrentTeb();

	if (*g_dwLastErrorToBreakOn && error == *g_dwLastErrorToBreakOn)
	{
		DebugBreak();
	}

	if (teb->LastErrorValue != error) // preventing same error from being processed twice
	{
		teb->LastErrorValue = error;
		
		if (error && error != ERROR_IO_PENDING && *g_isErrorOriginProviderEnabled)
		{
			EVENT_DATA_DESCRIPTOR EventDesc;
			EventDesc.Ptr = &error;
			EventDesc.Size = 4;
			return EtwEventWrite(*g_hUserDiagnosticProvider, SetLastWin32ErrorEvent, 1, &EventDesc);
		}
	}

	// returning TEB seems to indicate that the error is already queued
	// returning 0 indicates that you passed 0 as the code, which is not a valid error code
	return (INT64)teb;
}