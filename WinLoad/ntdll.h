#pragma once

// Enums

enum LDR_ENTRY_FLAGS // https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntldr/ldr_data_table_entry.htm
{
	PackagedBinary                 = 0x00000001,
	LDRP_MARKED_FOR_REMOVAL        = 0x00000002,
	LDRP_IMAGE_DLL                 = 0x00000004,
	LDRP_LOAD_NOTIFICATIONS_SENT   = 0x00000008,
	LDRP_TELEMETRY_ENTRY_PROCESSED = 0x00000010,
	ProcessStaticImport            = 0x00000020,
	InLegacyLists                  = 0x00000040,
	InIndexes                      = 0x00000080,
	ShimDll                        = 0x00000100,
	InExceptionTable               = 0x00000200,
	LDRP_LOAD_IN_PROGRESS          = 0x00001000,
	LoadConfigProcessed            = 0x00002000,
	LDRP_ENTRY_PROCESSED           = 0x00004000,
	ProtectDelayLoad               = 0x00008000,
	LDRP_DONT_CALL_FOR_THREADS     = 0x00040000,
	LDRP_PROCESS_ATTACH_CALLED     = 0x00080000,
	ProcessAttachFailed            = 0x00100000,
	CorDeferredValidate            = 0x00200000,
	LDRP_COR_IMAGE                 = 0x00400000,
	LDRP_DONT_RELOCATE             = 0x00800000,
	LDRP_COR_IL_ONLY               = 0x01000000,
	ChpeImage                      = 0x02000000,
	LDRP_REDIRECTED                = 0x10000000,
	CompatDatabaseProcessed        = 0x80000000,
};

enum LDR_DDAG_STATE // https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntldr/ldr_ddag_state.htm
{
	LdrModulesMerged                 = -5,
	LdrModulesInitError              = -4,
	LdrModulesSnapError              = -3,
	LdrModulesUnloaded               = -2,
	LdrModulesUnloading              = -1,
	LdrModulesPlaceHolder            =  0,
	LdrModulesMapping                =  1,
	LdrModulesMapped                 =  2,
	LdrModulesWaitingForDependencies =  3,
	LdrModulesSnapping               =  4,
	LdrModulesSnapped                =  5,
	LdrModulesCondensed              =  6,
	LdrModulesReadyToInit            =  7,
	LdrModulesInitializing           =  8,
	LdrModulesReadyToRun             =  9
};

enum API_MASKS // Used in ApiSetResolveToHost to check the validity of an API set's name
{
	API_HIGH      = 0x0002D0049,
	EXT_HIGH      = 0x0002D0054,
	API_LOW       = 0x000500041,
	EXT_LOW       = 0x000580045,
	API_MASK_LOW  = 0x0FFDFFFDF,
	API_MASK_HIGH = 0x0FFFFFFDF
};

// Typedefs

typedef SINGLE_LIST_ENTRY* LDRP_CSLIST;

// Structs

/*IN PROGRESS*/
struct LDR_DLL_DATA
{
	char Unk1[12];
	ULONG Flags;
	PWSTR DllName;
	char Unk2[58];
};

/*IN PROGRESS*/
struct LDRP_LOAD_CONTEXT
{
	UNICODE_STRING DllPath;
	LDR_DLL_DATA* DllData;
	char Pad1[4];
	ULONG Flags;
	char Pad2[4];
	NTSTATUS* pState;
	LDR_DATA_TABLE_ENTRY* ParentLdrEntry; // The dll that the load context's corresponding dll is a dependency of
	LDR_DATA_TABLE_ENTRY* LdrEntry; // Corresponding LdrEntry
	char Pad3[72];
	WCHAR DllPathStr[];
};

/*
* > LDRP_LOAD_CONTEXT
* 
* INITIALIZATION
* - Initialized in LdrpAllocatePlaceHolder
*/

struct LDR_DDAG_NODE // https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntldr/ldr_ddag_node.htm
{
	LIST_ENTRY Modules;
	struct LDR_SERVICE_TAG_RECORD* ServiceTagList;
	ULONG LoadCount;
	ULONG LoadWhileUnloadingCount;
	ULONG LowestLink;
	LDRP_CSLIST Dependencies;
	LDRP_CSLIST IncomingDependencies;
	LDR_DDAG_STATE State;
	SINGLE_LIST_ENTRY* CondenseLink;
	ULONG PreorderNumber;
};

typedef struct API_SET_VALUE_ENTRY
{
	DWORD Flags;
	DWORD NameOffset;
	DWORD NameLength;
	DWORD ValueOffset;
	DWORD ValueLength;
} HOST_ENTRY;

typedef struct NAMESPACE_HEADER
{
	DWORD SchemaExt;
	DWORD MapSizeByte;
	DWORD Flags;
	DWORD ApiSetCount;
	DWORD NsEntryOffset;
	DWORD HashOffset;
	DWORD Multiplier;
} API_SET_MAP;

typedef struct API_SET_NAMESPACE_ENTRY
{
	DWORD Flags;
	DWORD ApiNameOffset;
	DWORD ApiNameSz;
	DWORD ApiSubNameSz;
	DWORD HostEntryOffset;
	DWORD HostCount;
} NAMESPACE_ENTRY;

struct HASH_ENTRY
{
	DWORD ApiHash;
	DWORD ApiIndex;
};

// Function signatures

typedef NTSTATUS(__fastcall LdrpAllocatePlaceHolder)(UNICODE_STRING* DllPath, LDR_DLL_DATA* pDllData, ULONG Flags, INT LoadReason, LDR_DATA_TABLE_ENTRY* ParentEntry, LDR_DATA_TABLE_ENTRY** pLdrEntry, NTSTATUS* State);

typedef LONG(__stdcall RtlCompareUnicodeStrings)(_In_ PWSTR Str1, _In_ UINT Sz1, _In_ PWSTR Str2, _In_ UINT Sz2, _In_ bool CaseInsensitive); // Not the same as RtlCompareUnicodeString

typedef HOST_ENTRY* (__fastcall ApiSetpSearchForApiSetHost)(_In_ NAMESPACE_ENTRY* NsEntry, _In_ PWSTR HostName, _In_ UINT16 HostNameSz, _In_ NAMESPACE_HEADER* ApiSetMap);

typedef NAMESPACE_ENTRY* (__fastcall ApiSetpSearchForApiSet)(_In_ NAMESPACE_HEADER* ApiSetMap, _In_ PWSTR ApiName, _In_ UINT16 ApiSubNameSz);

typedef NTSTATUS(__fastcall ApiSetResolveToHost)(_In_ NAMESPACE_HEADER* ApiSetMap, _In_ UNICODE_STRING* ApiName, _In_opt_ UNICODE_STRING* ParentName, _Out_ bool* Resolved, _Out_ UNICODE_STRING* HostName);

typedef PWSTR(__stdcall RtlGetNtSystemRoot)(); // Exported

typedef NTSTATUS(__fastcall LdrpGetFullPath)(_In_ UNICODE_STRING* DllName, _Out_ UNICODE_STRING* DllPath);

typedef NTSTATUS(__fastcall LdrpPreprocessDllName)(_In_ UNICODE_STRING* DllName, _Out_ UNICODE_STRING* ProcessedName, _In_opt_ LDR_DATA_TABLE_ENTRY* ParentLdrEntry, _Inout_ ULONG* LoadFlags);