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
	char Pad2[8];
	LDR_DATA_TABLE_ENTRY* ParentLdrEntry; // The dll that the load context's corresponding dll is a dependency of
	LDR_DATA_TABLE_ENTRY* LdrEntry; // Corresponding LdrEntry
	char Pad3[72];
	WCHAR DllPathStr[];
};

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