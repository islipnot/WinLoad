#pragma once

// Enums

enum LOAD_CONTEXT_FLAGS
{
	Unknown0             = 0x0000001,
	Unknown1             = 0x0000008,
	Unknown2             = 0x0000200,
	Unknown3             = 0x0010000,
	Unknown5             = 0x0080000,
	Unknown4             = 0x0100000,
	UseActivationContext = 0x0800000,
	RedirectModuleImport = 0x2000000
};

enum LDR_ENTRY_MASKS // https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntldr/ldr_data_table_entry.htm
{
	PackagedBinary          = 0x00000001,
	MarkedForRemoval        = 0x00000002,
	ImageDll                = 0x00000004,
	LoadNotificationsSent   = 0x00000008,
	TelemetryEntryProcessed = 0x00000010,
	ProcessStaticImport     = 0x00000020,
	InLegacyLists           = 0x00000040,
	InIndexes               = 0x00000080,
	ShimDll                 = 0x00000100,
	InExceptionTable        = 0x00000200,
	LoadInProgress          = 0x00001000,
	LoadConfigProcessed     = 0x00002000,
	EntryProcessed          = 0x00004000,
	ProtectDelayLoad        = 0x00008000,
	DontCallForThreads      = 0x00040000,
	ProcessAttachCalled     = 0x00080000,
	ProcessAttachFailed     = 0x00100000,
	CorDeferredValidate     = 0x00200000,
	CorImage                = 0x00400000,
	DontRelocate            = 0x00800000,
	CorILOnly               = 0x01000000,
	ChpeImage               = 0x02000000,
	Redirected              = 0x10000000,
	CompatDatabaseProcessed = 0x80000000,
};

enum LDR_DLL_LOAD_REASON // https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntldr/ldr_data_table_entry.htm
{
	LoadReasonStaticDependency           =  0,
	LoadReasonStaticForwarderDependency  =  1,
	LoadReasonDynamicForwarderDependency =  2,
	LoadReasonDelayloadDependency        =  3,
	LoadReasonDynamicLoad                =  4,
	LoadReasonAsImageLoad                =  5,
	LoadReasonAsDataLoad                 =  6,
	LoadReasonEnclavePrimary             =  7,
	LoadReasonEnclaveDependency          =  8,
	LoadReasonUnknown                    = -1
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
	PWSTR DllPath;
	char Unk1[4];
	PWSTR PackageDirs;
	ULONG Flags;
	PWSTR DllName;
	char Unk2[58];
};

/*IN PROGRESS*/
typedef struct LDRP_LOAD_CONTEXT
{
	UNICODE_STRING DllPath;
	LDR_DLL_DATA* DllData;
	HMODULE Handle;
	ULONG Flags;
	char Pad1[4];
	NTSTATUS* pState;
	LDR_DATA_TABLE_ENTRY* ParentLdrEntry;
	LDR_DATA_TABLE_ENTRY* LdrEntry;
	char Pad2[8];
	LDR_DATA_TABLE_ENTRY* ReplacedModule;
	LDR_DATA_TABLE_ENTRY** DependencyLdrEntryArray;
	ULONG DependencyCount;
	ULONG DependencysWithIAT;
	IMAGE_THUNK_DATA32* IAT;
	ULONG IATSize;
	char Pad3[8];
	IMAGE_IMPORT_DESCRIPTOR* ImportDirectory;
	ULONG OldIATProtect;
	DWORD* GuardCFCheckFunctionPointer;
	DWORD GuardCFCheckFunctionPointerVA;
	ULONG Unk1;
	int Unk2;
	char Pad4[4];
	BYTE* DllSectionBase;
	WCHAR DllPathBase;
} LOAD_CONTEXT;

/* 
- Instances of LOAD_CONTEXT are initialized in LdrpAllocatePlaceHolder,
  though not all of the instances member's are initialized there.

- LOAD_CONTEXT::Handle is initialized near the end of LdrpMapDllNtFileName.

- LOAD_CONTEXT::DllPathBase is the base of an allocated buffer for the DllPath, 
  the size being equal to DllPath->Length (Allocated along with the load context 
  via RtlAllocateHeap, total size being DllPath->Length + 0x6E).

- LOAD_CONTEXT::DependencyCount is initialized in LdrpMapAndSnapDependency
  along with LOAD_CONTEXT::DependencyLdrEntryArray. That array is filled
  in LdrpLoadDependentModule. LOAD_CONTEXT::DependencysWithIAT is initialized
  in the same loop as DependencyCount, except its only incremented if the
  import descriptors corresponding IAT isn't null.
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

struct RTL_BALANCED_NODE // https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/shared/ntdef/rtl_balanced_node.htm
{
	union 
	{
		RTL_BALANCED_NODE* Children[2];
		struct 
		{
			RTL_BALANCED_NODE* Left;
			RTL_BALANCED_NODE* Right;
		};
	};
	union 
	{
		UCHAR Red : 1;
		UCHAR Balance : 2;
		ULONG_PTR ParentValue;
	};
};

struct __LDR_DATA_TABLE_ENTRY // https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntldr/ldr_data_table_entry.htm
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	union
	{
		LIST_ENTRY InInitializationOrderLinks;
		LIST_ENTRY InProgressLinks;
	};
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	union
	{
		UCHAR FlagGroup[4];
		ULONG Flags;
		struct
		{
			ULONG PackagedBinary : 1;
			ULONG MarkedForRemoval : 1;
			ULONG ImageDll : 1;
			ULONG LoadNotificationsSent : 1;
			ULONG TelemetryEntryProcessed : 1;
			ULONG ProcessStaticImport : 1;
			ULONG InLegacyLists : 1;
			ULONG InIndexes : 1;
			ULONG ShimDll : 1;
			ULONG InExceptionTable : 1;
			ULONG ReservedFlags1 : 2;
			ULONG LoadInProgress : 1;
			ULONG LoadConfigProcessed : 1;
			ULONG EntryProcessed : 1;
			ULONG ProtectDelayLoad : 1;
			ULONG ReservedFlags3 : 2;
			ULONG DontCallForThreads : 1;
			ULONG ProcessAttachCalled : 1;
			ULONG ProcessAttachFailed : 1;
			ULONG CorDeferredValidate : 1;
			ULONG CorImage : 1;
			ULONG DontRelocate : 1;
			ULONG CorILOnly : 1;
			ULONG ChpeImage : 1;
			ULONG ReservedFlags5 : 2;
			ULONG Redirected : 1;
			ULONG ReservedFlags6 : 2;
			ULONG CompatDatabaseProcessed : 1;
		};
	};
	USHORT ObsoleteLoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	ULONG TimeDateStamp;
	PVOID EntryPointActivationContext;
	PVOID Lock;
	LDR_DDAG_NODE* DdagNode;
	LIST_ENTRY NodeModuleLink;
	LOAD_CONTEXT* LoadContext;
	PVOID ParentDllBase;
	PVOID SwitchBackContext;
	RTL_BALANCED_NODE BaseAddressIndexNode;
	RTL_BALANCED_NODE MappingInfoIndexNode;
	ULONG_PTR OriginalBase;
	LARGE_INTEGER LoadTime;
	ULONG BaseNameHashValue; // Calculated via LdrpHashUnicodeString
	LDR_DLL_LOAD_REASON LoadReason;
	ULONG ImplicitPathOptions;
	ULONG ReferenceCount;
	ULONG DependentLoadFlags;
	UCHAR SigningLevel;
};

typedef struct API_SET_VALUE_ENTRY // https://www.geoffchappell.com/studies/windows/win32/apisetschema/index.htm
{
	DWORD Flags;
	DWORD NameOffset;
	DWORD NameLength;
	DWORD ValueOffset;
	DWORD ValueLength;
} HOST_ENTRY;

typedef struct NAMESPACE_HEADER // https://www.geoffchappell.com/studies/windows/win32/apisetschema/index.htm
{
	DWORD SchemaExt;
	DWORD MapSizeByte;
	DWORD Flags;
	DWORD ApiSetCount;
	DWORD NsEntryOffset;
	DWORD HashOffset;
	DWORD Multiplier;
} API_SET_MAP;

typedef struct API_SET_NAMESPACE_ENTRY // https://www.geoffchappell.com/studies/windows/win32/apisetschema/index.htm
{
	DWORD Flags;
	DWORD ApiNameOffset;
	DWORD ApiNameSz;
	DWORD ApiSubNameSz;
	DWORD HostEntryOffset;
	DWORD HostCount;
} NAMESPACE_ENTRY;

struct HASH_ENTRY // https://www.geoffchappell.com/studies/windows/win32/apisetschema/index.htm
{
	DWORD ApiHash;
	DWORD ApiIndex;
};