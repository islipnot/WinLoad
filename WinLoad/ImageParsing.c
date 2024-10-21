#include "pch.h"
#include "ntdll.h"

// https://www.intel.com/content/www/us/en/docs/cpp-compiler/developer-guide-reference/2021-8/addcarry-u32-addcarry-u64.html
extern unsigned char _addcarry_u32(unsigned char c_in, unsigned int src1, unsigned int src2, unsigned int* sum_out);

// https://www.intel.com/content/www/us/en/docs/cpp-compiler/developer-guide-reference/2021-8/subborrow-u32-subborrow-u64.html
extern unsigned char _subborrow_u32(unsigned char b_in, unsigned int src1, unsigned int src2, unsigned int* diff_out);

SECTION_HEADER* RtlSectionTableFromVirtualAddress(const NT_HEADERS* NtHeaders, DWORD VirtAddr) // 1:1 sig in sigs.h
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

void* RtlAddressInSectionTable(const NT_HEADERS* NtHeaders, const BYTE* base, DWORD VirtAddr)
{
	SECTION_HEADER* section = RtlSectionTableFromVirtualAddress(NtHeaders, VirtAddr);
	if (section) return &base[section->PointerToRawData - section->VirtualAddress + VirtAddr];
	else return 0;
}

NTSTATUS RtlpImageDirectoryEntryToData64(const BYTE* base, bool MappedAsImage, UINT16 DirEntry, ULONG* DirSize, const NT_HEADERS* NtHeaders, void** ResolvedAddress)
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

NTSTATUS RtlImageNtHeaderEx(ULONG flags, const DWORD* base, SIZE_T ViewSize, NT_HEADERS** pNtHeader) // 1:1 sig in sigs.h
{
	if (!pNtHeader) return STATUS_INVALID_PARAMETER;

	*pNtHeader = 0;

	if (flags & INVALID_FLAG_BITS || !base || base == (DWORD*)-1)
		return STATUS_INVALID_PARAMETER;

	bool CheckFileHdrOffset;

	if ((flags & IGNORE_VIEW_SIZE) != 0)
	{
		CheckFileHdrOffset = false;
	}
	else
	{
		CheckFileHdrOffset = true;
		if (ViewSize < 0x40) return STATUS_INVALID_IMAGE_FORMAT;
	}

	NTSTATUS result;
	NT_HEADERS* pNtHeaders = 0;

	if (*(WORD*)base == IMAGE_DOS_SIGNATURE)
	{
		const ULONG PeSigOffset = base[0xF]; // 0xF * sizeof(DWORD*) = 0x3C

		if (!CheckFileHdrOffset || PeSigOffset < ViewSize && PeSigOffset < 0xFFFFFFE7 && PeSigOffset + 0x18 < ViewSize)
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

NT_HEADERS* RtlImageNtHeader(const void* base)
{
	NT_HEADERS* NtHeader;
	RtlImageNtHeaderEx(IGNORE_VIEW_SIZE, (DWORD*)base, 0, &NtHeader);
	return NtHeader;
}

NTSTATUS RtlpImageDirectoryEntryToDataEx(const void* base, bool MappedAsImage, UINT16 DirEntry, ULONG* DirSize, void** ResolvedAddress)
{
	if (((UINT8)base & 3) != 0) // Checking alignment
	{
		if (((UINT8)base & 1) != 0)
			MappedAsImage = false;

		base = (void*)((UINT)base & 0xFFFFFFFC); // aligning base
	}

	NT_HEADERS* NtHeaders;
	NTSTATUS result = RtlImageNtHeaderEx(IGNORE_VIEW_SIZE, (DWORD*)base, 0, &NtHeaders);
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
		void* MappedAddr = RtlAddressInSectionTable(NtHeaders, base, VirtAddr);
		*ResolvedAddress = MappedAddr;

		if (MappedAddr) return STATUS_SUCCESS;
		return STATUS_INVALID_PARAMETER;
	}

	*ResolvedAddress = (char*)base + VirtAddr;
	return STATUS_SUCCESS;
}

void* RtlImageDirectoryEntryToData(const void* base, bool MappedAsImage, USHORT DirEntry, ULONG* DirSize)
{
	void* ResolvedAddress;
	return RtlpImageDirectoryEntryToDataEx(base, MappedAsImage, DirEntry, DirSize, &ResolvedAddress) < 0 ? 0 : ResolvedAddress;
}

bool LdrpValidateEntrySection(const DATA_TABLE_ENTRY* LdrEntry)
{
	NT_HEADERS* NtHeaders;
	RtlImageNtHeaderEx(IGNORE_VIEW_SIZE | NT_HDR_FLAG_RESERVED, (DWORD*)LdrEntry->DllBase, 0, &NtHeaders);

	const UINT AddressOfEP = NtHeaders->OptionalHeader.AddressOfEntryPoint;
	return !AddressOfEP || !LdrEntry->EntryPoint || AddressOfEP >= NtHeaders->OptionalHeader.SizeOfHeaders;
}

NTSTATUS LdrpCorValidateImage(const void* base)
{
	ULONG DirSize;
	return RtlImageDirectoryEntryToData(base, true, IMAGE_DIRECTORY_ENTRY_TLS, &DirSize) ? STATUS_SUCCESS : STATUS_INVALID_IMAGE_FORMAT;
}

int LdrpGenericProcessRelocation(const RELOC_DATA* RelocEntry, const BASE_RELOC* RelocBlock, DWORD LowBaseDif, DWORD HighBaseDif)
{
	const WORD RelocType = RelocEntry->Type;
	int ProcessedEntries = 1;

	if (RelocType != IMAGE_REL_BASED_ABSOLUTE)
	{
		void* RelocAddress = (void*)((char*)RelocBlock + RelocEntry->Offset);

		switch (RelocType)
		{
		case IMAGE_REL_BASED_HIGH:
		{
			*(WORD*)RelocAddress = (LowBaseDif + (*(WORD*)RelocAddress << 16)) >> 16;
			break;
		}

		case IMAGE_REL_BASED_LOW:
		{
			*(WORD*)RelocAddress += (WORD)LowBaseDif;
			break;
		}

		case IMAGE_REL_BASED_HIGHLOW:
		{
			*(DWORD*)RelocAddress += LowBaseDif;
			break;
		}

		case IMAGE_REL_BASED_HIGHADJ:
		{
			ProcessedEntries = 2;
			*(WORD*)RelocAddress = (LowBaseDif + (*(WORD*)RelocAddress << 16) + *(WORD*)&RelocEntry[1] + 0x8000) >> 16;
			break;
		}

		case IMAGE_REL_BASED_DIR64:
		{
			_addcarry_u32((UCHAR)((LowBaseDif + *(DWORD*)RelocAddress) == 0), *((UINT*)RelocAddress + 1), HighBaseDif, (UINT*)RelocAddress + 1);
			break;
		}

		default: ProcessedEntries = 0;
		}
	}

	return ProcessedEntries;
}

BASE_RELOC* LdrProcessRelocationBlockLongLong(UINT16 machine, const BASE_RELOC* RelocBlock, DWORD EntryCount, const RELOC_DATA* RelocEntry, DWORD LowBaseDif, DWORD HighBaseDif)
{
	RELOC_DATA* EndOfBlock = &RelocEntry[EntryCount];

	if (RelocEntry < EndOfBlock)
	{
		while (true)
		{
			// if ((1 << RelocEntry->Type & 0x3A0) != 0) Handle ARM/THUMB relocation (LdrpArmProcessRelocation/LdrpThumbProcessRelocation)

			const int result = LdrpGenericProcessRelocation(RelocEntry, RelocBlock, LowBaseDif, HighBaseDif);
			if (!result) return 0;

			RelocEntry += result;
			if (RelocEntry >= EndOfBlock) break;
		}
	}

	return (BASE_RELOC*)RelocEntry;
}

NTSTATUS LdrRelocateImageWithBias(const void* base)
{
	NT_HEADERS* NtHeaders;

	if (RtlImageNtHeaderEx(1, base, 0, &NtHeaders))
	{
		const WORD magic = NtHeaders->OptionalHeader.Magic;
		DWORD PreferredBaseLow, PreferredBaseHigh;

		if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
		{
			PreferredBaseLow = NtHeaders->OptionalHeader.ImageBase;
			PreferredBaseHigh = 0;
		}
		else
		{
			if (magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
				return STATUS_INVALID_IMAGE_FORMAT;

			PreferredBaseLow = NtHeaders->OptionalHeader.BaseOfData;
			PreferredBaseHigh = NtHeaders->OptionalHeader.ImageBase;
		}
		
		ULONG DirSize;
		BASE_RELOC* RelocBlock = (BASE_RELOC*)RtlImageDirectoryEntryToData(base, true, IMAGE_DIRECTORY_ENTRY_BASERELOC, &DirSize);

		if (!RelocBlock || !DirSize) return (NtHeaders->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) ? STATUS_SUCCESS : STATUS_CONFLICTING_ADDRESSES;

		UINT HighBaseDifference;
		_subborrow_u32((UCHAR)(((UINT)base - PreferredBaseLow) == 0), (UINT)base, PreferredBaseLow, &HighBaseDifference);

		const UINT LowBaseDifference = (UINT)base - PreferredBaseLow;

		while (true)
		{
			const DWORD SizeOfBlock = RelocBlock->SizeOfBlock;
			RelocBlock = LdrProcessRelocationBlockLongLong(NtHeaders->FileHeader.Machine, (BASE_RELOC*)((char*)base + RelocBlock->VirtualAddress),
				                                          (SizeOfBlock - sizeof(BASE_RELOC)) >> 1, (RELOC_DATA*)(RelocBlock + 1), LowBaseDifference, HighBaseDifference); 
			if (!RelocBlock) break;

			DirSize -= SizeOfBlock;
			if (!DirSize) return STATUS_SUCCESS;
		}
	}
	
	return STATUS_INVALID_IMAGE_FORMAT; 
}