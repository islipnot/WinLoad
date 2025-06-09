#pragma once
#include "pch.h"

//
// start of info from MSDN
//

ULONG WINAPI EtwEventWrite(
    __in REGHANDLE RegHandle,
    __in PCEVENT_DESCRIPTOR EventDescriptor,
    __in ULONG UserDataCount,
    __in_ecount_opt(UserDataCount) PEVENT_DATA_DESCRIPTOR UserData
) { return 0; }

//
// start of info from https://ntdoc.m417z.com
//

#define STATIC_UNICODE_BUFFER_LENGTH 261

#define GDI_BATCH_BUFFER_SIZE 310

#define WIN32_CLIENT_INFO_LENGTH 62

typedef struct _ACTIVATION_CONTEXT_STACK
{
    struct RTL_ACTIVATION_CONTEXT_STACK_FRAME* ActiveFrame;
    LIST_ENTRY FrameListCache;
    ULONG Flags;
    ULONG NextCookieSequenceNumber;
    ULONG StackId;
} ACTIVATION_CONTEXT_STACK, * PACTIVATION_CONTEXT_STACK;

typedef struct _GDI_TEB_BATCH
{
    ULONG Offset;
    ULONG_PTR HDC;
    ULONG Buffer[GDI_BATCH_BUFFER_SIZE];
} GDI_TEB_BATCH, * PGDI_TEB_BATCH;

typedef struct _TEB
{
    // Thread Information Block (TIB) contains the thread's stack, base and limit addresses, the current stack pointer, and the exception list.
    NT_TIB NtTib;

    // Reserved.
    PVOID EnvironmentPointer;

    // Client ID for this thread.
    CLIENT_ID ClientId;

    // A handle to an active Remote Procedure Call (RPC) if the thread is currently involved in an RPC operation.
    PVOID ActiveRpcHandle;

    // A pointer to the __declspec(thread) local storage array.
    PVOID ThreadLocalStoragePointer;

    // A pointer to the Process Environment Block (PEB), which contains information about the process.
    PPEB ProcessEnvironmentBlock;

    // The previous Win32 error value for this thread.
    ULONG LastErrorValue;

    // The number of critical sections currently owned by this thread.
    ULONG CountOfOwnedCriticalSections;

    // Reserved.
    PVOID CsrClientThread;

    // Reserved for GDI/USER (Win32k).
    PVOID Win32ThreadInfo;
    ULONG User32Reserved[26];
    ULONG UserReserved[5];

    // Reserved.
    PVOID WOW32Reserved;

    // The LCID of the current thread. (Kernel32!GetThreadLocale)
    LCID CurrentLocale;

    // Reserved.
    ULONG FpSoftwareStatusRegister;

    // Reserved.
    PVOID ReservedForDebuggerInstrumentation[16];

#ifdef _WIN64
    // Reserved.
    PVOID SystemReserved1[25];

    // Per-thread fiber local storage. (Teb->HasFiberData)
    PVOID HeapFlsData;

    // Reserved.
    ULONG_PTR RngState[4];
#else
    // Reserved.
    PVOID SystemReserved1[26];
#endif

    // Placeholder compatibility mode. (ProjFs and Cloud Files)
    CHAR PlaceholderCompatibilityMode;

    // Indicates whether placeholder hydration is always explicit.
    BOOLEAN PlaceholderHydrationAlwaysExplicit;

    // ProjFs and Cloud Files (reparse point) file virtualization.
    CHAR PlaceholderReserved[10];

    // The process ID (PID) that the current COM server thread is acting on behalf of.
    ULONG ProxiedProcessId;

    // Pointer to the activation context stack for the current thread.
    ACTIVATION_CONTEXT_STACK ActivationStack;

    // Opaque operation on behalf of another user or process.
    UCHAR WorkingOnBehalfTicket[8];

    // The last exception status for the current thread.
    NTSTATUS ExceptionCode;

    // Pointer to the activation context stack for the current thread.
    PACTIVATION_CONTEXT_STACK ActivationContextStackPointer;

    // The stack pointer (SP) of the current system call or exception during instrumentation.
    ULONG_PTR InstrumentationCallbackSp;

    // The program counter (PC) of the previous system call or exception during instrumentation.
    ULONG_PTR InstrumentationCallbackPreviousPc;

    // The stack pointer (SP) of the previous system call or exception during instrumentation.
    ULONG_PTR InstrumentationCallbackPreviousSp;

#ifdef _WIN64
    // The miniversion ID of the current transacted file operation.
    ULONG TxFsContext;
#endif

    // Indicates the state of the system call or exception instrumentation callback.
    BOOLEAN InstrumentationCallbackDisabled;

#ifdef _WIN64
    // Indicates the state of alignment exceptions for unaligned load/store operations.
    BOOLEAN UnalignedLoadStoreExceptions;
#endif

#ifndef _WIN64
    // SpareBytes.
    UCHAR SpareBytes[23];

    // The miniversion ID of the current transacted file operation.
    ULONG TxFsContext;
#endif

    // Reserved for GDI (Win32k).
    GDI_TEB_BATCH GdiTebBatch;
    CLIENT_ID RealClientId;
    HANDLE GdiCachedProcessHandle;
    ULONG GdiClientPID;
    ULONG GdiClientTID;
    PVOID GdiThreadLocalInfo;

    // Reserved for User32 (Win32k).
    ULONG_PTR Win32ClientInfo[WIN32_CLIENT_INFO_LENGTH];

    // Reserved for opengl32.dll
    PVOID glDispatchTable[233];
    ULONG_PTR glReserved1[29];
    PVOID glReserved2;
    PVOID glSectionInfo;
    PVOID glSection;
    PVOID glTable;
    PVOID glCurrentRC;
    PVOID glContext;

    // The previous status value for this thread.
    NTSTATUS LastStatusValue;

    // A static string for use by the application.
    UNICODE_STRING StaticUnicodeString;

    // A static buffer for use by the application.
    WCHAR StaticUnicodeBuffer[STATIC_UNICODE_BUFFER_LENGTH];

    // The maximum stack size and indicates the base of the stack.
    PVOID DeallocationStack;

    // Data for Thread Local Storage. (TlsGetValue)
    PVOID TlsSlots[TLS_MINIMUM_AVAILABLE];

    // Reserved for TLS.
    LIST_ENTRY TlsLinks;

    // Reserved for NTVDM.
    PVOID Vdm;

    // Reserved for RPC.
    PVOID ReservedForNtRpc;

    // Reserved for Debugging (DebugActiveProcess).
    PVOID DbgSsReserved[2];

    // The error mode for the current thread. (GetThreadErrorMode)
    ULONG HardErrorMode;

    // Reserved.
#ifdef _WIN64
    PVOID Instrumentation[11];
#else
    PVOID Instrumentation[9];
#endif

    // Reserved.
    GUID ActivityId;

    // The identifier of the service that created the thread. (svchost)
    PVOID SubProcessTag;

    // Reserved.
    PVOID PerflibData;

    // Reserved.
    PVOID EtwTraceData;

    // The address of a socket handle during a blocking socket operation. (WSAStartup)
    HANDLE WinSockData;

    // The number of function calls accumulated in the current GDI batch. (GdiSetBatchLimit)
    ULONG GdiBatchCount;

    // The preferred processor for the current thread. (SetThreadIdealProcessor/SetThreadIdealProcessorEx)
    union
    {
        PROCESSOR_NUMBER CurrentIdealProcessor;
        ULONG IdealProcessorValue;
        struct
        {
            UCHAR ReservedPad0;
            UCHAR ReservedPad1;
            UCHAR ReservedPad2;
            UCHAR IdealProcessor;
        };
    };

    // The minimum size of the stack available during any stack overflow exceptions. (SetThreadStackGuarantee)
    ULONG GuaranteedStackBytes;

    // Reserved.
    PVOID ReservedForPerf;

    // Reserved for Object Linking and Embedding (OLE)
    struct SOleTlsData* ReservedForOle;

    // Indicates whether the thread is waiting on the loader lock.
    ULONG WaitingOnLoaderLock;

    // The saved priority state for the thread.
    PVOID SavedPriorityState;

    // Reserved.
    ULONG_PTR ReservedForCodeCoverage;

    // Reserved.
    PVOID ThreadPoolData;

    // Pointer to the TLS (Thread Local Storage) expansion slots for the thread.
    PVOID* TlsExpansionSlots;

#ifdef _WIN64
    PVOID ChpeV2CpuAreaInfo; // CHPEV2_CPUAREA_INFO // previously DeallocationBStore
    PVOID Unused; // previously BStoreLimit
#endif

    // The generation of the MUI (Multilingual User Interface) data.
    ULONG MuiGeneration;

    // Indicates whether the thread is impersonating another security context.
    ULONG IsImpersonating;

    // Pointer to the NLS (National Language Support) cache.
    PVOID NlsCache;

    // Pointer to the AppCompat/Shim Engine data.
    PVOID pShimData;

    // Reserved.
    ULONG HeapData;

    // Handle to the current transaction associated with the thread.
    HANDLE CurrentTransactionHandle;

    // Pointer to the active frame for the thread.
    struct TEB_ACTIVE_FRAME* ActiveFrame;

    // Reserved for FLS (RtlProcessFlsData).
    PVOID FlsData;

    // Pointer to the preferred languages for the current thread. (GetThreadPreferredUILanguages)
    PVOID PreferredLanguages;

    // Pointer to the user-preferred languages for the current thread. (GetUserPreferredUILanguages)
    PVOID UserPrefLanguages;

    // Pointer to the merged preferred languages for the current thread. (MUI_MERGE_USER_FALLBACK)
    PVOID MergedPrefLanguages;

    // Indicates whether the thread is impersonating another user's language settings.
    ULONG MuiImpersonation;

    // Reserved.
    union
    {
        USHORT CrossTebFlags;
        USHORT SpareCrossTebBits : 16;
    };

    // SameTebFlags modify the state and behavior of the current thread.
    union
    {
        USHORT SameTebFlags;
        struct
        {
            USHORT SafeThunkCall : 1;
            USHORT InDebugPrint : 1;            // Indicates if the thread is currently in a debug print routine.
            USHORT HasFiberData : 1;            // Indicates if the thread has local fiber-local storage (FLS).
            USHORT SkipThreadAttach : 1;        // Indicates if the thread should suppress DLL_THREAD_ATTACH notifications.
            USHORT WerInShipAssertCode : 1;
            USHORT RanProcessInit : 1;          // Indicates if the thread has run process initialization code.
            USHORT ClonedThread : 1;            // Indicates if the thread is a clone of a different thread.
            USHORT SuppressDebugMsg : 1;        // Indicates if the thread should suppress LOAD_DLL_DEBUG_INFO notifications.
            USHORT DisableUserStackWalk : 1;
            USHORT RtlExceptionAttached : 1;
            USHORT InitialThread : 1;           // Indicates if the thread is the initial thread of the process.
            USHORT SessionAware : 1;
            USHORT LoadOwner : 1;               // Indicates if the thread is the owner of the process loader lock.
            USHORT LoaderWorker : 1;
            USHORT SkipLoaderInit : 1;
            USHORT SkipFileAPIBrokering : 1;
        };
    };

    // Pointer to the callback function that is called when a KTM transaction scope is entered.
    PVOID TxnScopeEnterCallback;

    // Pointer to the callback function that is called when a KTM transaction scope is exited.
    PVOID TxnScopeExitCallback;

    // Pointer to optional context data for use by the application when a KTM transaction scope callback is called.
    PVOID TxnScopeContext;

    // The lock count of critical sections for the current thread.
    ULONG LockCount;

    // The offset to the WOW64 (Windows on Windows) TEB for the current thread.
    LONG WowTebOffset;

    // Reserved.
    PVOID ResourceRetValue;

    // Reserved for Windows Driver Framework (WDF).
    PVOID ReservedForWdf;

    // Reserved for the Microsoft C runtime (CRT).
    ULONGLONG ReservedForCrt;

    // The Host Compute Service (HCS) container identifier.
    GUID EffectiveContainerId;

    // Reserved for Kernel32!Sleep (SpinWait).
    ULONGLONG LastSleepCounter; // since Win11

    // Reserved for Kernel32!Sleep (SpinWait).
    ULONG SpinCallCount;

    // Extended feature disable mask (AVX).
    ULONGLONG ExtendedFeatureDisableMask;

    // Reserved.
    PVOID SchedulerSharedDataSlot; // since 24H2

    // Reserved.
    PVOID HeapWalkContext;

    // The primary processor group affinity of the thread.
    GROUP_AFFINITY PrimaryGroupAffinity;

    // Read-copy-update (RCU) synchronization context.
    ULONG Rcu[2];
} TEB, * PTEB;

//
// end of info from https://ntdoc.m417z.com
//

//
// GLOBAL VARIABLES
//

// The last error thrown that requires a debug break
UINT32* g_dwLastErrorToBreakOn = 0x18016DBA4;

// If true, error origins can be traced
BOOLEAN* g_isErrorOriginProviderEnabled = 0x18016D734;

// Irrelevant/unclear
REGHANDLE* g_hUserDiagnosticProvider = 0x18016AC40;

// Event descriptor for EtwEventWrite
BOOLEAN* SetLastWin32ErrorEvent = 0x180132388;

//
// FUNCTION SIGNATURES
//

INT64 __fastcall RtlSetLastWin32Error(UINT error);