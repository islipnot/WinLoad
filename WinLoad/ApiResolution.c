#include "pch.h"
#include "ntdll.h"

HOST_ENTRY* ApiSetpSearchForApiSetHost(const NAMESPACE_ENTRY* NsEntry, const PWSTR HostName, UINT16 HostNameSz, const NAMESPACE_HEADER* ApiSetMap)
{
	const DWORD HostEntryOffset = NsEntry->HostEntryOffset;
	HOST_ENTRY* FirstHostEntry = (HOST_ENTRY*)((char*)(ApiSetMap) + HostEntryOffset);

	int UpperBound = 1;
	int LowerBound = NsEntry->HostCount - 1;
	int NextUpperBound = 1;

	if (LowerBound >= 1) // Checking if the host count is greater than 1 (highest seen host count in windows is 2).
	{
		const DWORD dwHostNameSz = (DWORD)HostNameSz;
		const DWORD dwApiSetMap = (DWORD)ApiSetMap;

		do
		{
			const DWORD EntryIndex = (LowerBound + UpperBound) >> 1;
			HOST_ENTRY* HostEntry = (HOST_ENTRY*)(dwApiSetMap + HostEntryOffset + (sizeof(HOST_ENTRY) * EntryIndex));

			// The actual function uses RtlCompareUnicodeStrings here.
			const int StrDif = _wcsnicmp(HostName, (PWSTR)(dwApiSetMap + HostEntry->NameOffset), HostEntry->NameLength >> 1);

			if (StrDif < 0)
			{
				UpperBound = NextUpperBound;
				LowerBound = EntryIndex - 1;
			}
			else
			{
				if (!StrDif) return HostEntry;

				UpperBound = EntryIndex + 1;
				NextUpperBound = EntryIndex + 1;
			}
		} while (UpperBound <= LowerBound);
	}
	
	return FirstHostEntry;
}

NAMESPACE_ENTRY* ApiSetpSearchForApiSet(const NAMESPACE_HEADER* ApiSetMap, PWSTR ApiName, UINT16 ApiSubNameSz)
{
	DWORD ApiHash = 0;

	if (ApiSubNameSz) // Hashing API Set name
	{
		PWSTR pApiName = ApiName;

		for (int i = ApiSubNameSz;; --i)
		{
			WCHAR ch = *pApiName;

			if ((UINT16)(ch - 65) <= 25u) // Casting to UINT16 prevents non-letters ('-'/digits) from being converted
				ch += 32; // Converting char to lowercase if its uppercase

			++pApiName;
			ApiHash = ch + (ApiSetMap->Multiplier * ApiHash);

			if (!i) break;
		}
	}

	int UpperBound = 0;
	int LowerBound = ApiSetMap->ApiSetCount - 1;
	if (LowerBound < 0) return 0;

	DWORD HashOffset = ApiSetMap->HashOffset;
	DWORD HashEntryOffset;

	while (true) // Getting API set's corresponding HASH_TABLE entry
	{
		const int EntryIndex = (LowerBound + UpperBound) >> 1;
		HashEntryOffset = HashOffset + (sizeof(HASH_ENTRY) * EntryIndex);

		if (ApiHash < *(DWORD*)((char*)(ApiSetMap) + HashEntryOffset))
		{
			LowerBound = EntryIndex - 1;
		}
		else
		{
			if (ApiHash <= *(DWORD*)((char*)(ApiSetMap) + HashEntryOffset))
				break;

			UpperBound = EntryIndex + 1;
		}

		if (UpperBound > LowerBound)
			return 0;
	}

	const DWORD NsEntryOffset = ApiSetMap->NsEntryOffset + (sizeof(NAMESPACE_ENTRY) * *(DWORD*)((char*)ApiSetMap + HashEntryOffset + 4));
	NAMESPACE_ENTRY* NsEntry = (NAMESPACE_ENTRY*)((char*)ApiSetMap + NsEntryOffset);
	
	if (!NsEntry) return 0;

	// The actual function uses RtlCompareUnicodeStrings here, but that's not worth calling GetProcAddress for.
	if (_wcsnicmp(ApiName, (PCWSTR)((char*)ApiSetMap + NsEntry->ApiNameOffset), ApiSubNameSz) == 0)
		return NsEntry;

	return 0;
}

NTSTATUS ApiSetResolveToHost(const NAMESPACE_HEADER* ApiSetMap, const UNICODE_STRING* ApiName, const UNICODE_STRING* ParentName, bool* pResolved, UNICODE_STRING* HostName)
{
	bool resolved = false;

	HostName->Length = 0;
	HostName->Buffer = 0;

	const UINT NameLen = (UINT)ApiName->Length;

	if (NameLen >= 8) // wcslen(L"api-") * sizeof(WCHAR) == wcslen(L"ext-") * sizeof(WCHAR) == 8
	{
		const PWSTR pApiName = ApiName->Buffer;
		const DWORD Mask1 = *(DWORD*)pApiName & API_MASK_LOW;
		const DWORD Mask2 = *((DWORD*)pApiName + 1) & API_MASK_HIGH;

		if ((Mask1 == API_LOW && Mask2 == API_HIGH) || (Mask1 == EXT_LOW && Mask2 == EXT_HIGH))
		{
			UINT16 wSubNameSz = (UINT16)NameLen;
			PWCHAR ch = (PWCHAR)((char*)pApiName + wSubNameSz);

			do
			{
				if (wSubNameSz <= 1)
					break;

				--ch;
				wSubNameSz -= 2;
			} 
			while (*ch != '-');

			const UINT16 SubNameSz = (UINT16)wSubNameSz >> 1;

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
					else HostEntry = (HOST_ENTRY*)((char*)ApiSetMap + NsEntry->HostEntryOffset);

					if (NsEntry->HostCount)
					{
						resolved = true;
						HostName->Buffer = (PWSTR)((char*)ApiSetMap + HostEntry->ValueOffset);
						HostName->MaximumLength = HostName->Length = (USHORT)HostEntry->ValueLength;
					}
				}
			}
		}
	}

	*pResolved = resolved;
	return STATUS_SUCCESS;
}

NTSTATUS ApiSetQuerySchemaInfo(const NAMESPACE_HEADER* ApiSetMap, const UNICODE_STRING* Namespace, BOOLEAN* pIsInSchema, BOOLEAN* pPresent)
{
	const UINT NsLength = (UINT)Namespace->Length;
	const PWSTR NsBuffer = Namespace->Buffer;
	bool IsApiSet = false;

	if (NsLength >= 8) // wcslen(L"api-") * sizeof(WCHAR) == wcslen(L"ext-") * sizeof(WCHAR) == 8
	{
		const DWORD NsMaskHigh = *(DWORD*)NsBuffer & API_MASK_LOW;
		const DWORD NsMaskLow  = *((DWORD*)NsBuffer + 1) & API_MASK_HIGH;
		IsApiSet = NsMaskHigh == API_LOW && NsMaskLow == API_HIGH || NsMaskHigh == EXT_LOW && NsMaskLow == EXT_HIGH;
	}

	if (!IsApiSet)
	{
		if (!_wcsnicmp(L"SchemaExt-", NsBuffer, 20))
		{
			*pPresent = *pIsInSchema = ApiSetpSearchForApiSet(ApiSetMap, NsBuffer, (UINT16)NsLength >> 1) != 0;
			return STATUS_SUCCESS;
		}

		return STATUS_INVALID_PARAMETER;
	}

	UINT ApiSubNameSz = NsLength;

	if (NsLength > 1)
	{
		PWCHAR NameEnd = (PWCHAR)((char*)NsBuffer + NsLength);

		do
		{
			--NameEnd;
			ApiSubNameSz -= 2;
		} 
		while (*NameEnd != '-' && ApiSubNameSz > 1);
	}

	const UINT SubCharCount = (UINT16)ApiSubNameSz >> 1;
	if (!(UINT16)SubCharCount) return STATUS_INVALID_PARAMETER;

	const UINT DetailLen = (NsLength - (UINT16)ApiSubNameSz) >> 1;
	if (DetailLen < 2) return STATUS_INVALID_PARAMETER;

	const PWSTR ApiDetailsDash = (PWSTR)((char*)NsBuffer + (UINT16)ApiSubNameSz);
	if (*ApiDetailsDash != '-') return STATUS_INVALID_PARAMETER;

	DWORD DetailHash = 0;

	if ((int)(DetailLen - 1) > 0)
	{
		PWCHAR ApiDetails = ApiDetailsDash + 1;
		int DetailIndex = DetailLen - 1;

		do
		{
			const int detail = *ApiDetails;

			if ((UINT16)(detail - 48) > 9)
			{
				return STATUS_INVALID_PARAMETER;
			}

			++ApiDetails;
			--DetailIndex;
			DetailHash = detail + (10 * DetailHash) - 48;
		} 
		while (DetailIndex > 0);
	}

	const NAMESPACE_ENTRY* NsEntry = ApiSetpSearchForApiSet(ApiSetMap, NsBuffer, SubCharCount);

	bool InSchema = false;
	bool present = false;

	if (NsEntry)
	{
		const UINT NseDetailSzDash = (NsEntry->ApiNameSz - NsEntry->ApiSubNameSz) >> 1;

		if (NseDetailSzDash)
		{
			const PWSTR NseDetailsDash = (PWSTR)((char*)ApiSetMap + NsEntry->ApiSubNameSz + NsEntry->ApiNameOffset);

			if (*NseDetailsDash == '-' && NseDetailSzDash != 1)
			{
				UINT NseDetailSz = NseDetailSzDash - 1;
				PWSTR NseDetails = NseDetailsDash + 1;
				UINT NseHash = 0;

				if ((int)(NseDetailSzDash - 1) < 1)
				{
				check_if_in_schema:

					if (DetailHash <= NseHash)
					{
						InSchema = true;
						if (NsEntry->HostCount) present = *(DWORD*)((char*)&ApiSetMap->NsEntryOffset + NsEntry->HostEntryOffset) != 0; // Checking if the host's API_SET_VALUE_ENTRY::ValueLength is non-zero
					}
				}
				else
				{
					while ((UINT16)(*NseDetails - 48) <= 9)
					{
						NseDetails = *NseDetails++;
						NseHash = NseDetails + (10 * NseHash) - 48;
						if ((int)--NseDetailSz < 1) goto check_if_in_schema;
					}
				}
			}
		}
	}

	*pIsInSchema = InSchema;
	*pPresent = present;
	return STATUS_SUCCESS;
}

NTSTATUS LdrpParseForwarderDescription(const char* forwarder, STRING* DllName, char** pExportName, const ULONG* ordinal)
{
	char* LastPeriod = strrchr(forwarder, '.');

	if (LastPeriod)
	{
		const UINT DllNameSz = LastPeriod - forwarder;

		if (DllNameSz <= 0xFFFF)
		{
			DllName->Buffer = forwarder;
			DllName->MaximumLength = DllName->Length = (USHORT)DllNameSz;

			char* ExportName;

			if (LastPeriod[1] != '#')
			{
				ExportName = LastPeriod + 1;
				
			SetExportName:
				*pExportName = ExportName;
				return STATUS_SUCCESS;
			}

			ExportName = 0;

			if (RtlCharToInteger(LastPeriod + 2, 0, ordinal) >= 0)
				goto SetExportName;
		}
	}

	return STATUS_INVALID_IMAGE_FORMAT;
}

int main() { return 0; }