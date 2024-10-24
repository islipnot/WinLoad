#pragma once

// Enums

typedef enum _RTL_NT_HDR_FLAGS // RtlImageNtHeader/RtlImageNtHeaderEx
{
	IGNORE_VIEW_SIZE     = 1,
	NT_HDR_FLAG_RESERVED = 2,
	INVALID_FLAG_BITS    = 0xFFFFFFFC,
} RTL_NT_HDR_FLAGS, NT_HDR_FLAGS;

/* UNFINISHED */
typedef enum _LDRP_LOAD_CONTEXT_FLAGS
{
	DontUseCOR       = 0x0000001, // LdrpInitializeProcess
	Unknown1         = 0x0000008, // Used in LdrpLoadKnownDll/LdrpFindLoadedDllByNameLockHeld
	Unknown0         = 0x0000020, // Used in LdrpLoadKnownDll/LdrpMapDllWithSectionHandle
	Unknown6         = 0x0000100, // Used in LdrpMapDllNtFileName, 
	Unknown2         = 0x0000200, // LdrpInitializeProcess/LdrpLoadKnownDll
	Unknown8         = 0x0000800, // Used in LdrpLoadDependentModule
	Unknown7         = 0x0008000, // LdrpAllocatePlaceHolder - used in LdrpFreeLoadContext
	Unknown3         = 0x0010000,
	Unknown5         = 0x0080000, // LdrpSnapModule - used in LdrpHandleReplacedModule
	Unknown4         = 0x0100000, // LdrpCheckForRetryLoading
	ContextCorImage  = 0x0400000, // LdrpCompleteMapModule
	Unknown9         = 0x0800000, // Used in LdrpMinimalMapModule/LdrpMapDllWithSectionHandle
	ContextCorILOnly = 0x1000000, // LdrpCompleteMapModule
	RedirectModule   = 0x2000000  // LdrpMapAndSnapDependency
} LDRP_LOAD_CONTEXT_FLAGS, LOAD_CONTEXT_FLAGS;

typedef enum _LDR_ENTRY_FLAGS // https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntldr/ldr_data_table_entry.htm
{
	PackagedBinary          = 0x00000001,
	MarkedForRemoval        = 0x00000002,
	ImageDll                = 0x00000004,
	LoadNotificationsSent   = 0x00000008,
	TelemetryEntryProcessed = 0x00000010,
	ProcessStaticImport     = 0x00000020,
	InLegacyLists           = 0x00000040,
	InIndexes               = 0x00000080, // LdrpInsertModuleToIndexLockHeld
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
	CorImage                = 0x00400000, // LdrpCompleteMapModule
	DontRelocate            = 0x00800000,
	CorILOnly               = 0x01000000, // LdrpCompleteMapModule
	ChpeImage               = 0x02000000,
	Redirected              = 0x10000000,
	CompatDatabaseProcessed = 0x80000000,
} LDR_ENTRY_MASKS;

typedef enum _LDR_DLL_LOAD_REASON // https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntldr/ldr_data_table_entry.htm
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
} LDR_DLL_LOAD_REASON, DLL_LOAD_REASON;

typedef enum _LDR_DDAG_STATE // https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntldr/ldr_ddag_state.htm
{
	LdrModulesMerged                 = -5,
	LdrModulesInitError              = -4,
	LdrModulesSnapError              = -3,
	LdrModulesUnloaded               = -2,
	LdrModulesUnloading              = -1,
	LdrModulesPlaceHolder            =  0,
	LdrModulesMapping                =  1,
	LdrModulesMapped                 =  2, // LdrpProcessMappedModule
	LdrModulesWaitingForDependencies =  3,
	LdrModulesSnapping               =  4,
	LdrModulesSnapped                =  5,
	LdrModulesCondensed              =  6,
	LdrModulesReadyToInit            =  7,
	LdrModulesInitializing           =  8,
	LdrModulesReadyToRun             =  9
} LDR_DDAG_STATE;

enum STRING_MASKS
{
	// ApiSetQuerySchemaInfo/ApiSetResolveToHost
	API_MASK_HIGH = 0x0FFFFFFDF,
	API_MASK_LOW  = 0x0FFDFFFDF,
	API_HIGH      = 0x0002D0049, // "AP"
	API_LOW       = 0x000500041, // "I" (following char isn't checked)
	EXT_HIGH      = 0x0002D0054, // "T" (following char isn't checked)
	EXT_LOW       = 0x000580045, // "EX"

	// LdrpResolveForwarder
	NTDLL_MASK  = 0x020202020, // Converts any upper/lowercase combo of "ntdl" to lowercase
	NTDLL_ASCII = 0x06C64746E  // "ntdl"
};

// Typedefs

typedef SINGLE_LIST_ENTRY* LDRP_CSLIST;

typedef IMAGE_NT_HEADERS32 NT_HEADERS;

typedef IMAGE_SECTION_HEADER SECTION_HEADER;

typedef IMAGE_OPTIONAL_HEADER32 OPTIONAL_HEADER;

typedef IMAGE_IMPORT_DESCRIPTOR IMPORT_DESCRIPTOR;

typedef IMAGE_COR20_HEADER COM_DESCRIPTOR, COR20_HEADER, CLR_HEADER;

typedef IMAGE_BASE_RELOCATION BASE_RELOCATION, BASE_RELOC;

typedef IMAGE_LOAD_CONFIG_DIRECTORY32 LOAD_CONFIG;

// Structs (comments are the functions where they're initialized)

typedef struct _PE_IMAGE_CREATION_INFO // LdrpMapDllWithSectionHandle (passed to LdrpFindLoadedDllByMappingLockHeld)
{
	UINT TimeDateStamp; // NtHeader->FileHeader.TimeDateStamp
	UINT SizeOfImage;   // NtHeader->OptionalHeader.SizeOfImage
} PE_IMAGE_CREATION_INFO;

/* REAL STRUCT NAME UNKNOWN */
typedef struct _LDRP_INVERTED_FUNCTION_TABLE_ENTRY // RtlpInsertInvertedFunctionTableEntry
{
	union // RtlEncodeSystemPointer/RtlDecodeSystemPointer (inlined)
	{
		DWORD SEHandlerTable; // RtlpxLookupFunctionTable
		DWORD SEHandlerTableEncoded; // RtlInsertInvertedFunctionTable
	};

	void* DllBase;        // Base of the function table's corresponding dll
	UINT SizeOfImage;
	DWORD SEHandlerCount; // LOAD_CONFIG::SEHandlerCount
} LDRP_INVERTED_FUNCTION_TABLE_ENTRY, INVERTED_FUNCTION_TABLE_ENTRY;

typedef struct _LDRP_DLL_DIR_DATA // LoadLibraryExW
{
	PWSTR Directory; // LdrGetDllPath (called from KernelBase.dll!LoadLibraryExW)
	PWSTR Path;      // LdrGetDllPath (called from KernelBase.dll!LoadLibraryExW)
} LDRP_DLL_DIR_DATA;

/* UNFINISHED - REAL STRUCT NAME UNKNOWN */
typedef struct _LDRP_MODULE_PATH_DATA // LdrLoadDll/LdrGetDllHandleEx
{
	union
	{
		struct // LdrpInitializeDllPath
		{
			PWSTR ModulePath;
			DWORD dwFlags;
		};
		
		UNICODE_STRING UnicodeModulePath; // LdrpComputeLazyDllPath
	};

	PWSTR PackageDirs;
	ULONG ImplicitPathOptions; // LdrpInitializeDllPath
	PWSTR ModuleName; // LdrpInitializeDllPath
	WCHAR CachedPath[26];

	union
	{
		DWORD DwordUnk2;
		BYTE BytesUnk2[4];
	};
	
	char padding[2];
} LDRP_MODULE_PATH_DATA, MODULE_PATH_DATA;

/* UNFINISHED */
typedef struct __declspec(align(4)) _LDRP_LOAD_CONTEXT // LdrpAllocatePlaceHolder (dll context), LdrpInitializeProcess (process context)
{
	UNICODE_STRING ModuleName; // LdrpAllocatePlaceHolder
	MODULE_PATH_DATA* PathData; // LdrpAllocatePlaceHolder
	HANDLE SectionHandle;   // LdrpMapDllNtFileName
	union // Flags are accessed both as a ULONG and a bitfield, depending on the function.
	{
		ULONG Flags;      // LdrpAllocatePlaceHolder
		BYTE FlagGroup[4];
		struct
		{
			ULONG DontUseCOR : 1;
			ULONG Unk1 : 25;
			ULONG ContextCorImage : 1;
			ULONG UseActivationContext : 1;
			ULONG ContextCorILOnly : 1;
			ULONG RedirectModule : 1;
			ULONG Unk2 : 2;
		};
	};
	char reserved[4]; // Haven't seen this used at all, and load context's are freed after the image is loaded.
	NTSTATUS* pState; // LdrpAllocatePlaceHolder
	struct DATA_TABLE_ENTRY* ParentLdrEntry; // LdrpAllocatePlaceHolder
	struct DATA_TABLE_ENTRY* LdrEntry;       // LdrpAllocateModuleEntry
	DWORD* LdrpWorkQueue;   // LdrpQueueWork
	DWORD** pLdrpWorkQueue; // LdrpQueueWork/LdrpCheckForRetryLoading
	struct DATA_TABLE_ENTRY* ReplacedModule;
	struct DATA_TABLE_ENTRY** DependencyEntryList; // LdrpMapAndSnapDependency
	ULONG DependencyCount;    // LdrpMapAndSnapDependency
	ULONG DependencysWithIAT; // LdrpMapAndSnapDependency
	void* IATSection;    // LdrpPrepareImportAddressTableForSnap - base of section that contains IAT
	UINT IATSectionSize; // LdrpPrepareImportAddressTableForSnap - size of section that contains IAT
	ULONG DependencyIndex; // LdrpSnapModule (DependencyEntryList)
	ULONG IATIndex;        // LdrpSnapModule
	IMAGE_IMPORT_DESCRIPTOR* ImportDirectory; // LdrpMapAndSnapDependency
	ULONG OldIATProtect;
	DWORD* GuardCFCheckFunctionPointer;
	DWORD GuardCFCheckFunctionPointerVA;
	SIZE_T ViewSize; // LdrpMinimalMapModule
	bool UnknownBool; // Used in LdrpMinimalMapModule/LdrpCheckForRetryLoading/LdrpMapDllFullPath
	HANDLE FileHandle; // LdrpMapDllNtFileName (initialized as INVALID_HANDLE_VALUE in LdrpAllocatePlaceHolder)
	BYTE* ModuleSectionBase;
	WCHAR ModuleNameBase;
} LDRP_LOAD_CONTEXT, LOAD_CONTEXT;

typedef struct _LDR_DDAG_NODE // https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntldr/ldr_ddag_node.htm
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
} LDR_DDAG_NODE;

typedef struct _RTL_BALANCED_NODE // https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/shared/ntdef/rtl_balanced_node.htm
{
	union 
	{
		struct _RTL_BALANCED_NODE* Children[2];
		struct 
		{
			struct _RTL_BALANCED_NODE* Left;
			struct _RTL_BALANCED_NODE* Right;
		};
	};
	union 
	{
		UCHAR Red : 1;
		UCHAR Balance : 2;
		ULONG_PTR ParentValue;
	};
} RTL_BALANCED_NODE;

typedef struct _RTL_RB_TREE // https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/shared/rtlrbtree/rtl_rb_tree.htm
{
	RTL_BALANCED_NODE* Root;
	RTL_BALANCED_NODE* Min;
} RTL_RB_TREE;

typedef struct _FULL_LDR_DATA_TABLE_ENTRY // https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntldr/ldr_data_table_entry.htm
{
	LIST_ENTRY InLoadOrderLinks; // LdrpInsertDataTableEntry
	LIST_ENTRY InMemoryOrderLinks; // LdrpInsertDataTableEntry
	union
	{
		LIST_ENTRY InInitializationOrderLinks;
		LIST_ENTRY InProgressLinks;
	};
	PVOID DllBase; // LdrpMinimalMapModule
	PVOID EntryPoint; // LdrpProcessMappedModule
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
			ULONG ImageDll : 1; // LdrpAllocateModuleEntry
			ULONG LoadNotificationsSent : 1;
			ULONG TelemetryEntryProcessed : 1;
			ULONG ProcessStaticImport : 1; // LdrpAllocateModuleEntry
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
			ULONG DontCallForThreads  : 1;
			ULONG ProcessAttachCalled : 1;
			ULONG ProcessAttachFailed : 1;
			ULONG CorDeferredValidate : 1;
			ULONG CorImage : 1;
			ULONG DontRelocate : 1;
			ULONG CorILOnly : 1;
			ULONG ChpeImage : 1;
			ULONG ReservedFlags5 : 2;
			ULONG Redirected : 1; // LdrpAllocateModuleEntry
			ULONG ReservedFlags6 : 2;
			ULONG CompatDatabaseProcessed : 1;
		};
	};
	USHORT ObsoleteLoadCount; // LdrpAllocateModuleEntry
	USHORT TlsIndex;
	LIST_ENTRY HashLinks; // LdrpInsertDataTableEntry
	ULONG TimeDateStamp;
	PVOID EntryPointActivationContext;
	PVOID Lock;
	LDR_DDAG_NODE* DdagNode;
	LIST_ENTRY NodeModuleLink;
	LOAD_CONTEXT* LoadContext; // LdrpAllocateModuleEntry
	PVOID ParentDllBase;
	PVOID SwitchBackContext;
	RTL_BALANCED_NODE BaseAddressIndexNode;
	RTL_BALANCED_NODE MappingInfoIndexNode;
	ULONG_PTR OriginalBase; // LdrpProcessMappedModule
	LARGE_INTEGER LoadTime;
	ULONG BaseNameHashValue; // LdrpInsertDataTableEntry (calulated via LdrpHashUnicodeString)
	DLL_LOAD_REASON LoadReason;
	ULONG ImplicitPathOptions; // LdrpAllocateModuleEntry (LoadContext->PathData->ImplicitPathOptions)
	ULONG ReferenceCount;
	ULONG DependentLoadFlags;
	UCHAR SigningLevel;
} FULL_LDR_DATA_TABLE_ENTRY, DATA_TABLE_ENTRY;

typedef struct _MODULE_LIST_ENTRY
{
	LIST_ENTRY ListEntry;
	DATA_TABLE_ENTRY* LdrEntry;
} MODULE_LIST_ENTRY;

typedef struct _API_SET_VALUE_ENTRY // https://www.geoffchappell.com/studies/windows/win32/apisetschema/index.htm
{
	DWORD Flags;
	DWORD NameOffset;
	DWORD NameLength;
	DWORD ValueOffset;
	DWORD ValueLength;
} API_SET_VALUE_ENTRY, HOST_ENTRY;

typedef struct _NAMESPACE_HEADER // https://www.geoffchappell.com/studies/windows/win32/apisetschema/index.htm
{
	DWORD SchemaExt;
	DWORD MapSizeByte;
	DWORD Flags;
	DWORD ApiSetCount;
	DWORD NsEntryOffset;
	DWORD HashOffset;
	DWORD Multiplier;
} NAMESPACE_HEADER, API_SET_MAP;

typedef struct _API_SET_NAMESPACE_ENTRY // https://www.geoffchappell.com/studies/windows/win32/apisetschema/index.htm
{
	DWORD Flags;
	DWORD ApiNameOffset;
	DWORD ApiNameSz;
	DWORD ApiSubNameSz;
	DWORD HostEntryOffset;
	DWORD HostCount;
} API_SET_NAMESPACE_ENTRY, NAMESPACE_ENTRY;

typedef struct _HASH_ENTRY // https://www.geoffchappell.com/studies/windows/win32/apisetschema/index.htm
{
	DWORD ApiHash;
	DWORD ApiIndex;
} HASH_ENTRY;

typedef struct _FULL_PEB_LDR_DATA // https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntpsapi_x/peb_ldr_data.htm
{
	ULONG Length;
	BOOLEAN Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
	BOOLEAN ShutdownInProgress;
	HANDLE ShutdownThreadId;
} FULL_PEB_LDR_DATA;

typedef struct _FULL_PEB // https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/pebteb/peb/index.htm
{
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	union 
	{
		UCHAR BitField;
		struct 
		{
			UCHAR ImageUsedLargePages : 1;
			UCHAR IsProtectedProcess : 1;
			UCHAR IsImageDynamicallyRelocated : 1;
			UCHAR SkipPatchingUser32Forwarders : 1;
			UCHAR IsPackagedProcess : 1;
			UCHAR IsAppContainer : 1;
			UCHAR IsProtectedProcessLight : 1;
			UCHAR IsLongPathAwareProcess : 1;
		};
	};
	HANDLE Mutant;
	PVOID ImageBaseAddress;
	FULL_PEB_LDR_DATA* Ldr;
	RTL_USER_PROCESS_PARAMETERS* ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	RTL_CRITICAL_SECTION* FastPebLock;
	PVOID AtlThunkSListPtr;
	PVOID IFEOKey;
	union 
	{
		ULONG CrossProcessFlags;
		struct 
		{
			ULONG ProcessInJob : 1;
			ULONG ProcessInitializing : 1;
			ULONG ProcessUsingVEH : 1;
			ULONG ProcessUsingVCH : 1;
			ULONG ProcessUsingFTH : 1;
			ULONG ProcessPreviouslyThrottled : 1;
			ULONG ProcessCurrentlyThrottled : 1;
			ULONG ProcessImagesHotPatched : 1;
			ULONG ReservedBits0 : 24;
		};
	};
	union 
	{
		PVOID KernelCallbackTable;
		PVOID UserSharedInfoPtr;
	};
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	NAMESPACE_HEADER* ApiSetMap;
	ULONG TlsExpansionCounter;
	PVOID TlsBitmap;
	ULONG TlsBitmapBits[2];
	PVOID ReadOnlySharedMemoryBase;
	PVOID SharedData;
	PVOID* ReadOnlyStaticServerData;
	PVOID AnsiCodePageData;
	PVOID OemCodePageData;
	PVOID UnicodeCaseTableData;
	ULONG NumberOfProcessors;
	ULONG NtGlobalFlag;
	LARGE_INTEGER CriticalSectionTimeout;
	ULONG_PTR HeapSegmentReserve;
	ULONG_PTR HeapSegmentCommit;
	ULONG_PTR HeapDeCommitTotalFreeThreshold;
	ULONG_PTR HeapDeCommitFreeBlockThreshold;
	ULONG NumberOfHeaps;
	ULONG MaximumNumberOfHeaps;
	PVOID* ProcessHeaps;
	PVOID GdiSharedHandleTable;
	PVOID ProcessStarterHelper;
	ULONG GdiDCAttributeList;
	RTL_CRITICAL_SECTION* LoaderLock;
	ULONG OSMajorVersion;
	ULONG OSMinorVersion;
	USHORT OSBuildNumber;
	USHORT OSCSDVersion;
	ULONG OSPlatformId;
	ULONG ImageSubsystem;
	ULONG ImageSubsystemMajorVersion;
	ULONG ImageSubsystemMinorVersion;
	KAFFINITY ActiveProcessAffinityMask;
	ULONG GdiHandleBuffer[0x22];
	VOID(*PostProcessInitRoutine) (VOID);
	PVOID TlsExpansionBitmap;
	ULONG TlsExpansionBitmapBits[0x20];
	ULONG SessionId;
	ULARGE_INTEGER AppCompatFlags;
	ULARGE_INTEGER AppCompatFlagsUser;
	PVOID pShimData;
	PVOID AppCompatInfo;
	UNICODE_STRING CSDVersion;
	struct ACTIVATION_CONTEXT_DATA const* ActivationContextData;
	struct ASSEMBLY_STORAGE_MAP* ProcessAssemblyStorageMap;
	struct ACTIVATION_CONTEXT_DATA const* SystemDefaultActivationContextData;
	struct ASSEMBLY_STORAGE_MAP* SystemAssemblyStorageMap;
	ULONG_PTR MinimumStackCommit;
	PVOID SparePointers[4];
	ULONG SpareUlongs[5];
	PVOID WerRegistrationData;
	PVOID WerShipAssertPtr;
	PVOID pUnused;
	PVOID pImageHeaderHash;
	union 
	{
		ULONG TracingFlags;
		struct 
		{
			ULONG HeapTracingEnabled : 1;
			ULONG CritSecTracingEnabled : 1;
			ULONG LibLoaderTracingEnabled : 1;
			ULONG SpareTracingBits : 29;
		};
	};
	ULONGLONG CsrServerReadOnlySharedMemoryBase;
	ULONG TppWorkerpListLock;
	LIST_ENTRY TppWorkerpList;
	PVOID WaitOnAddressHashTable[0x80];
	PVOID TelemetryCoverageHeader;
	ULONG CloudFileFlags;
	ULONG CloudFileDiagFlags;
	CHAR PlaceholderCompatibiltyMode;
	CHAR PlaceholderCompatibilityModeReserved[7];
	struct LEAP_SECOND_DATA* LeapSecondData;
	union 
	{
		ULONG LeapSecondFlags;
		struct 
		{
			ULONG SixtySecondEnabled : 1;
			ULONG Reserved : 31;
		};
	};
	ULONG NtGlobalFlag2;
} FULL_PEB;

typedef struct _FILE_NETWORK_OPEN_INFORMATION // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_file_network_open_information
{
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER AllocationSize;
	LARGE_INTEGER EndOfFile;
	ULONG         FileAttributes;
} FILE_NETWORK_OPEN_INFORMATION, * PFILE_NETWORK_OPEN_INFORMATION;

/* Unsure if Microsoft uses a struct like or just manual bit manipulation */
typedef struct _RELOC_DATA
{
	WORD Offset : 12;
	WORD Type : 4;
} RELOC_DATA;

/* REAL STRUCT NAME UNKNOWN */
typedef struct _IMPORT_INFO // LdrpCheckRedirection
{
	DWORD ImportHash; // LdrpHashAsciizString
	DWORD BaseNameHashValue; // LDR_DATA_TABLE_ENTRY::BaseNameHashValue of the dll the import belongs to
	char* ImportName; // ASCII name of the import
} IMPORT_INFO;

// Global variables

#define SystemRootAddress   0x7FFE0030

#define PebSystemRootOffset 0x1E

#define PtrEncryptionCookie 0x7FFE0330

// Notes

/*

> LdrpHashTable (global var)
- Doubly linked list with 32 LIST_ENTRY's
- Initialized in LdrpInitializeProcess
- Entries are accessed with the equation "EntryIndex = LdrEntry.BaseNameHashValue & 0x1F"

> LdrpImageEntry (global var)
- Initialized in LdrpInitializeProcess as a pointer to the main executable's LDR_DATA_TABLE_ENTRY

> _RTL_NT_HDR_FLAGS
- I've only seen the reserved flag used in combination with DONT_CHECK_FILE_HDR_OFFSET
  in LdrpValidateEntrySection, but it's not used in any way besides being counted 
  towards the flag validity check, which just tests the flags against INVALID_FLAG_BITS

> Global pointer encryption key ( MEMORY[0x7FFE0330] )
- Static key used for pointer encryption/decryption

> Global windows directory string ( MEMORY[0x7FFE0030] )
- A wide string of the current windows installation directory (Example: L"c:\\Windows")

> LdrpSaferIsDllAllowedRoutine (global var)
- Initialized in LdrpCodeAuthzInitialize as a pointer to ADVAPI32.DLL!SaferiIsDllAllowed
- Inline encoded with the same method as EncodeSystemPointer

> LDRP_MODULE_PATH_DATA
- This struct isn't exclusive to instances of LDRP_LOAD_CONTEXT, it can be seen
  initialized and used on its own in LdrGetDllHandleEx, and then destroyed at
  the end of the function. So the comments next to members aren't the only places
  where the members are initialized/used

> LDRP_LOAD_CONTEXT
- The load context of a module seems to always be freed once the image is fully 
  loaded. However, the corresponding LDR_DATA_TABLE_ENTRY::LoadContext still 
  points to where the load context used to be. Ntdll's LoadContext entry, as
  far as I know, is the only one that will be null, which it will always be.

*/

// Extra

inline FULL_PEB* NtCurrentPeb()
{
	return (FULL_PEB*)__readfsdword(FIELD_OFFSET(TEB, ProcessEnvironmentBlock));
}
 
/* Exported and included in windows.h(not 1:1) */
static __declspec(naked) void* __fastcall PtrEncode(void* ptr) // EncodeSystemPointer recreation
{
	__asm
	{
		push edx
		mov eax, ds:0x7FFE0330
		xor ecx, eax  // ptr ^= cookie
		and eax, 0x1F // cookie & 0x1F
		mov edx, ecx
		mov ecx, eax
		ror edx, cl
		mov eax, edx
		pop edx
		ret
	}
}

/* Exported and included in windows.h(not 1:1) */
static __declspec(naked) void* __fastcall PtrDecode(void* EncryptedPtr) // DecodeSystemPointer recreation
{
	__asm
	{
		push edi
		push edx
		push ecx
		mov eax, ds:0x7FFE0330
		mov edi, eax
		and edi, 0x1F
		push 32
		pop ecx
		sub ecx, edi
		pop edi
		ror edi, cl
		xor eax, edi
		pop edx
		pop edi
		ret
	}
}