#define DONT_DEFINE_FUNCTIONS

#include "pch.h"
#include "ntdll.h"

HOST_ENTRY* __fastcall ApiSetpSearchForApiSetHost(_In_ NAMESPACE_ENTRY* NsEntry, _In_ PWSTR HostName, _In_ UINT16 HostNameSz, _In_ NAMESPACE_HEADER* ApiSetMap)
{

}

NAMESPACE_ENTRY* __fastcall ApiSetpSearchForApiSet(_In_ NAMESPACE_HEADER* ApiSetMap, _In_ PWSTR ApiName, _In_ UINT16 ApiSubNameSz)
{

}

NTSTATUS __fastcall ApiSetResolveToHost(NAMESPACE_HEADER* ApiSetMap, UNICODE_STRING* ApiName, UNICODE_STRING* ParentName, bool* pResolved, UNICODE_STRING* HostName)
{
	bool resolved = false;

	HostName->Length = 0;
	HostName->Buffer = nullptr;

	const UINT NameLen = static_cast<UINT>(ApiName->Length);

	if (NameLen >= 8) // wcslen(L"api-") * sizeof(WCHAR) == wcslen(L"ext-") * sizeof(WCHAR) == 8
	{
		const PWSTR pApiName = ApiName->Buffer;
		const DWORD Mask1 = *reinterpret_cast<DWORD*>(pApiName) & API_MASK_LOW;
		const DWORD Mask2 = *(reinterpret_cast<DWORD*>(pApiName) + 1) & API_MASK_HIGH;

		if ((Mask1 == API_LOW && Mask2 == API_HIGH) || (Mask1 == EXT_LOW && Mask2 == EXT_HIGH))
		{
			UINT16 wSubNameSz = static_cast<UINT16>(NameLen);
			PWCHAR ch = reinterpret_cast<PWCHAR>(reinterpret_cast<char*>(pApiName) + wSubNameSz);

			do
			{
				if (wSubNameSz <= 1)
					break;

				--ch;
				wSubNameSz -= 2;
			} 
			while (*ch != '-');

			const UINT16 SubNameSz = static_cast<UINT16>(wSubNameSz) >> 1;

			if (SubNameSz)
			{
				NAMESPACE_ENTRY* NsEntry = ApiSetpSearchForApiSet(ApiSetMap, pApiName, SubNameSz);

				if (NsEntry)
				{
					HOST_ENTRY* HostEntry;

					if (ParentName && NsEntry->HostCount > 1)
					{
						HostEntry = ApiSetpSearchForApiSetHost(NsEntry, ParentName->Buffer, ParentName->Length >> 1, ApiSetMap);
					}
					else HostEntry = reinterpret_cast<HOST_ENTRY*>(reinterpret_cast<char*>(ApiSetMap) + NsEntry->HostEntryOffset);

					if (NsEntry->HostCount)
					{
						resolved = true;
						HostName->Buffer = reinterpret_cast<PWSTR>(reinterpret_cast<char*>(ApiSetMap) + HostEntry->ValueOffset);
						HostName->MaximumLength = HostName->Length = HostEntry->ValueLength;
					}
				}
			}
		}
	}

	*pResolved = resolved;
	return STATUS_SUCCESS;
}

int main()
{
	return 0;
}