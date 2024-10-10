#include "pch.h"
#include "ntdll.h"

SECTION_HEADER* RtlSectionTableFromVirtualAddress(NT_HEADERS* NtHeaders, DWORD VirtAddr) // 1:1 function signature in sigs.h
{
	const UINT NumberOfSections = (UINT)NtHeaders->FileHeader.NumberOfSections;
	if (!NumberOfSections) return 0;

	SECTION_HEADER* section = (SECTION_HEADER*)((char*)&NtHeaders->OptionalHeader + NtHeaders->FileHeader.SizeOfOptionalHeader);

	for (UINT i = 0; VirtAddr < section->VirtualAddress || VirtAddr >= section->VirtualAddress + section->SizeOfRawData;)
	{
		++section;

		if (++i >= NumberOfSections)
			return 0;
	}

	return section;
}

void* __stdcall RtlAddressInSectionTable(NT_HEADERS* NtHeaders, BYTE* base, DWORD VirtAddr)
{
	SECTION_HEADER* section = RtlSectionTableFromVirtualAddress(NtHeaders, VirtAddr);
	if (section) return &base[section->PointerToRawData - section->VirtualAddress + VirtAddr];
	else return 0;
}

NTSTATUS __fastcall RtlpImageDirectoryEntryToData64(BYTE* base, bool MappedAsImage, UINT16 DirEntry, ULONG* DirSize, NT_HEADERS* NtHeaders, void** ResolvedAddress)
{
	if (DirEntry < NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
	{
		const DWORD VirtAddr = NtHeaders->OptionalHeader.DataDirectory[DirEntry + 2].VirtualAddress;
		if (!VirtAddr) return STATUS_NOT_IMPLEMENTED;

		*DirSize = NtHeaders->OptionalHeader.DataDirectory[DirEntry + 2].Size;

		if (MappedAsImage || VirtAddr < NtHeaders->OptionalHeader.SizeOfHeaders)
		{
			*ResolvedAddress = &base[VirtAddr];
			return STATUS_SUCCESS;
		}
		
		void* address = RtlAddressInSectionTable(NtHeaders, base, VirtAddr);
		*ResolvedAddress = address;

		if (address) return STATUS_SUCCESS;
	}

	return STATUS_INVALID_PARAMETER;
}

NTSTATUS __stdcall RtlImageNtHeaderEx(ULONG flags, DWORD* base, ULONG size, NT_HEADERS** pNtHeader) // 1:1 function signature in sigs.h
{
	if (!pNtHeader) return STATUS_INVALID_PARAMETER;

	*pNtHeader = 0;

	if (flags & 0xFFFFFFFC || !base || base == (DWORD*)-1) // 0xFFFFFFFC = ~ValidFlags
		return STATUS_INVALID_PARAMETER;

	bool UnknownFlag;

	if ((flags & 1) != 0)
	{
		UnknownFlag = false;
	}
	else
	{
		UnknownFlag = true;
		if (size < 0x40) return STATUS_INVALID_IMAGE_FORMAT;
	}

	NTSTATUS result;
	NT_HEADERS* pNtHeaders = 0;

	if (*(WORD*)base == IMAGE_DOS_SIGNATURE)
	{
		const ULONG PeSigOffset = base[0xF]; // 0xF * sizeof(DWORD*) = 0x3C

		if (!UnknownFlag || PeSigOffset < size && PeSigOffset < 0xFFFFFFE7 && PeSigOffset + 0x18 < size)
		{
			if (PeSigOffset >= 0x10000000)
			{
				result = STATUS_INVALID_IMAGE_FORMAT;
			}
			else
			{
				pNtHeaders = (NT_HEADERS*)((char*)base + PeSigOffset);

				if ((DWORD*)pNtHeaders < base)
				{
					result = STATUS_INVALID_IMAGE_FORMAT;
				}
				else if (pNtHeaders->Signature == IMAGE_NT_SIGNATURE)
				{
					result = STATUS_SUCCESS;
				}
				else result = STATUS_INVALID_IMAGE_FORMAT;
			}
		}
		else result = STATUS_INVALID_IMAGE_FORMAT;

	}
	else result = STATUS_INVALID_IMAGE_FORMAT;

	if (result >= 0) *pNtHeader = pNtHeaders;
	return result;
}

NTSTATUS __fastcall RtlpImageDirectoryEntryToDataEx(void* base, bool MappedAsImage, UINT16 DirEntry, ULONG* DirSize, void** ResolvedAddress)
{
	if (((UINT8)base & 3) != 0) // Checking alignment
	{
		if (((UINT8)base & 1) != 0)
			MappedAsImage = false;

		base = (void*)((UINT)base & 0xFFFFFFFC); // aligning base
	}

	NT_HEADERS* NtHeaders;
	NTSTATUS result = RtlImageNtHeaderEx(1u, (DWORD*)base, 0, &NtHeaders);
	if (!NtHeaders) return result;

	const WORD magic = NtHeaders->OptionalHeader.Magic;
	if (magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		{
			return RtlpImageDirectoryEntryToData64(base, MappedAsImage, DirEntry, DirSize, NtHeaders, ResolvedAddress);
		}

		return STATUS_INVALID_PARAMETER;
	}

	if (DirEntry >= NtHeaders->OptionalHeader.NumberOfRvaAndSizes)
		return STATUS_INVALID_PARAMETER;

	const DWORD VirtAddr = NtHeaders->OptionalHeader.DataDirectory[DirEntry].VirtualAddress;
	if (!VirtAddr) return STATUS_NOT_IMPLEMENTED;

	*DirSize = NtHeaders->OptionalHeader.DataDirectory[DirEntry].Size;

	if (!MappedAsImage && VirtAddr >= NtHeaders->OptionalHeader.SizeOfHeaders)
	{
		const void* MappedAddr = RtlAddressInSectionTable(NtHeaders, base, VirtAddr);
		*ResolvedAddress = MappedAddr;

		if (MappedAddr) return STATUS_SUCCESS;
		return STATUS_INVALID_PARAMETER;
	}

	*ResolvedAddress = (char*)base + VirtAddr;
	return STATUS_SUCCESS;
}

void* __stdcall RtlImageDirectoryEntryToData(void* base, bool MappedAsImage, USHORT DirEntry, ULONG* DirSize)
{
	void* ResolvedAddress;

	if (RtlpImageDirectoryEntryToDataEx(base, MappedAsImage, DirEntry, DirSize, &ResolvedAddress))
	{
		return 0;
	}
	else return ResolvedAddress;
}