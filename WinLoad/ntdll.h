#pragma once

// Structs

/*IN PROGRESS*/
struct LDR_DLL_DATA
{
	char Unk1[12];
	ULONG Flags;
	PWSTR DllName;
	char Unk2[58];
};

/*
* INITIALIZATION
* - 
* 
* USES
* - 
* 
* INFO
* - 
*/

/*IN PROGRESS*/
struct LDRP_LOAD_CONTEXT // IN PROGRESS
{
	UNICODE_STRING DllPath;
	LDR_DLL_DATA* DllData;
	char Pad1[4];
	ULONG Flags;
	char Pad2[8];
	LDR_DATA_TABLE_ENTRY* ParentLdrEntry;
	LDR_DATA_TABLE_ENTRY* DllLdrEntry;
	char Pad3[72];
	WCHAR DllPathStr[];
};

/*
* INITIALIZATION
* -
*
* USES
* -
* 
* INFO
* - Sz = 0x6C + 
*/