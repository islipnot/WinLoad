#pragma once

#include "pch.h"
#include "ntdll.h"

typedef NTSTATUS(__fastcall LdrpAllocatePlaceHolder)(_Inout_ UNICODE_STRING* DllPath, _In_ MODULE_PATH_DATA* PathData, _In_ ULONG LoadFlags, _In_ DLL_LOAD_REASON LoadReason, _In_ DATA_TABLE_ENTRY* ParentEntry, _Out_ DATA_TABLE_ENTRY** NewEntry, _In_ NTSTATUS* pState);

typedef LONG(__stdcall RtlCompareUnicodeStrings)(_In_ PWSTR Str1, _In_ UINT Sz1, _In_ PWSTR Str2, _In_ UINT Sz2, _In_ bool CaseInsensitive); // Not the same as RtlCompareUnicodeString

typedef HOST_ENTRY* (__fastcall ApiSetpSearchForApiSetHost)(_In_ NAMESPACE_ENTRY* NsEntry, _In_ PWSTR HostName, _In_ UINT16 HostNameSz, _In_ NAMESPACE_HEADER* ApiSetMap);

typedef NAMESPACE_ENTRY* (__fastcall ApiSetpSearchForApiSet)(_In_ NAMESPACE_HEADER* ApiSetMap, _In_ PWSTR ApiName, _In_ UINT16 ApiSubNameSz);

typedef NTSTATUS(__fastcall ApiSetResolveToHost)(_In_ NAMESPACE_HEADER* ApiSetMap, _In_ UNICODE_STRING* ApiName, _In_opt_ UNICODE_STRING* ParentName, _Out_ bool* Resolved, _Out_ UNICODE_STRING* HostName);

typedef PWSTR(__stdcall RtlGetNtSystemRoot)(); // Exported

typedef NTSTATUS(__fastcall LdrpGetFullPath)(_In_ UNICODE_STRING* DllName, _Out_ UNICODE_STRING* DllPath);

typedef NTSTATUS(__fastcall LdrpPreprocessDllName)(_In_ UNICODE_STRING* DllName, _Out_ UNICODE_STRING* ProcessedName, _In_opt_ DATA_TABLE_ENTRY* ParentLdrEntry, _Inout_ ULONG* LoadFlags);

typedef NTSTATUS(__fastcall LdrpParseForwarderDescription)(_In_ char* Forwarder, _Out_ STRING* DllName, _Out_ char** ExportName, _In_ ULONG Ordinal);

typedef UINT(__stdcall LdrStandardizeSystemPath)(_Inout_ UNICODE_STRING* Path); // Exported

typedef NTSTATUS(__fastcall LdrpComputeLazyDllPath)(_Inout_ MODULE_PATH_DATA* DllData);

typedef NTSTATUS(__fastcall LdrpMapDllRetry)(_Inout_ LOAD_CONTEXT* LoadContext);

typedef NTSTATUS(__fastcall LdrpMapDllFullPath)(_Inout_ LOAD_CONTEXT* LoadContext);

typedef NTSTATUS(__fastcall LdrpMapDllNtFileName)(_Inout_ LOAD_CONTEXT* LoadContext, _In_ UNICODE_STRING* ObjName);

typedef NTSTATUS(__fastcall LdrpMapDllWithSectionHandle)(_Inout_ LOAD_CONTEXT* LoadContext);

typedef ULONG(__fastcall LdrpHashUnicodeString)(_In_ UNICODE_STRING* Str);

typedef NTSTATUS(__fastcall LdrpCorProcessImports)(_Inout_ LDR_DATA_TABLE_ENTRY* LdrEntry);

typedef NTSTATUS* (__fastcall LdrpMapAndSnapDependency)(_Inout_ LOAD_CONTEXT* LoadContext);

typedef NTSTATUS(__fastcall LdrpPrepareImportAddressTableForSnap)(_Inout_ LOAD_CONTEXT* LoadContext);

typedef bool(__fastcall LdrpShouldModuleImportBeRedirected)(_In_ DATA_TABLE_ENTRY* LdrEntry);

typedef IMPORT_DESCRIPTOR* (__fastcall LdrpGetImportDescriptorForSnap)(_Inout_ LOAD_CONTEXT* LoadContext);

typedef NTSTATUS(__fastcall RtlpImageDirectoryEntryToDataEx)(_In_ void* Base, _In_ bool MappedAsImage, _In_ UINT16 DirectoryEntry, _Out_ ULONG* DirSize, _Out_ void** ResolvedAddress);

typedef NTSTATUS(__fastcall LdrpMapCleanModuleView)(_Inout_ LOAD_CONTEXT* LoadContext);

typedef NTSTATUS(__fastcall LdrpProcessWork)(_Inout_ LOAD_CONTEXT* LoadContext, _In_ bool IsLoadOwner);

typedef DATA_TABLE_ENTRY* (__fastcall LdrpHandleReplacedModule)(_Inout_ DATA_TABLE_ENTRY* LdrEntry);

typedef PVOID(__fastcall LdrpQueueWork)(_Inout_ LOAD_CONTEXT* LoadContext);

typedef NTSTATUS(__stdcall LdrpInitParallelLoadingSupport)();

typedef NTSTATUS(__fastcall LdrpSnapModule)(_Inout_ LOAD_CONTEXT* LoadContext);

typedef NTSTATUS(__stdcall LdrLoadDll)(_In_ ULONG dwFlags, _In_opt_ ULONG DllCharacteristics, _In_ UNICODE_STRING* DllName, _Inout_ HMODULE* pHandle); // Exported

typedef void(__fastcall LdrpInitializeDllPath)(_In_ PWSTR DllName, _In_ ULONG dwFlags, _Inout_ MODULE_PATH_DATA* DllData);

typedef DATA_TABLE_ENTRY* (__fastcall LdrpAllocateModuleEntry)(_Inout_ LOAD_CONTEXT* LoadContext);

typedef NTSTATUS(__fastcall LdrpFindOrPrepareLoadingModule)(_Inout_ UNICODE_STRING DllPath, _In_ MODULE_PATH_DATA* PathData, _In_ ULONG LoadFlags, _In_ DLL_LOAD_REASON LdrFlags, _In_ DATA_TABLE_ENTRY* ParentEntry, _Out_ DATA_TABLE_ENTRY** NewEntry, _In_ NTSTATUS* pState);

typedef NTSTATUS(__fastcall LdrpLoadKnownDll)(_Inout_ LOAD_CONTEXT* LoadContext);

typedef NTSTATUS(__fastcall LdrpCorValidateImage)(_In_ void* Base);

typedef void* (__stdcall RtlImageDirectoryEntryToData)(_In_ void* Base, _In_ bool MappedAsImage, _In_ UINT16 DirEntry, _Out_ ULONG* DirSize); // Exported

typedef NTSTATUS(__fastcall RtlpImageDirectoryEntryToDataEx)(_In_ void* Base, _In_ bool MappedAsImage, _In_ UINT16 DirEntry, _Out_ ULONG* DirSize, _Out_ void** ResolvedAddress);

typedef NTSTATUS(__stdcall RtlImageNtHeaderEx)(_In_ ULONG Flags, _In_ DWORD* Base, _In_ ULONG FileHdrOffset, _In_opt_ int ReservedAlwaysZero, _Out_ NT_HEADERS** NtHeaders); // Exported

typedef NTSTATUS(__fastcall RtlpImageDirectoryEntryToData64)(_In_ BYTE* Base, _In_ bool MappedAsImage, _In_ UINT16 DirectoryEntry, _Out_ ULONG* DirectorySize, _In_ NT_HEADERS* NtHeaders, _Out_ void** ResolvedAddress);

typedef void* (__stdcall RtlAddressInSectionTable)(_In_ NT_HEADERS* NtHeaders, _In_ BYTE* Base, _In_ DWORD VirtAddress);

typedef SECTION_HEADER* (__thiscall RtlSectionTableFromVirtualAddress)(_In_ NT_HEADERS* NtHeaders, _In_ DWORD VirtAddress);

typedef NTSTATUS(__fastcall LdrpCompleteMapModule)(_In_ LOAD_CONTEXT* LoadContext, _In_ NT_HEADERS* NtHeaders, _In_ NTSTATUS ImageStatus);

typedef bool(__fastcall LdrpIsILOnlyImage)(_In_ void* base);

typedef NTSTATUS(__fastcall LdrpRelocateImage)(_In_ void* base, _In_ DWORD FileHdrOffset, _In_ NT_HEADERS* NtHeaders, _In_ UNICODE_STRING* DllName);

typedef NTSTATUS(__fastcall LdrpProtectAndRelocateImage)(_In_ void* base);

typedef NTSTATUS(__fastcall LdrRelocateImageWithBias)(_In_ void* base);

typedef RELOC_DATA* (__fastcall LdrProcessRelocationBlockLongLong)(_In_ UINT16 machine, _In_ BASE_RELOC* RelocBlock, _In_ UINT EntryCount, _Inout_ RELOC_DATA* RelocData, _In_ DWORD LowBaseDif, _In_ DWORD HighBaseDif);

typedef NTSTATUS(__fastcall LdrpProcessMappedModule)(_Inout_ DATA_TABLE_ENTRY* LdrEntry, _In_ ULONG ContextFlags);

typedef bool(__fastcall LdrpValidateEntrySection)(_In_ DATA_TABLE_ENTRY* LdrEntry);

typedef NTSTATUS(__stdcall LdrpInitializeImportRedirection)();

typedef DWORD(__fastcall LdrpHashAsciizString)(_In_ char* str);

typedef NTSTATUS(__fastcall ApiSetQuerySchemaInfo)(_In_ NAMESPACE_HEADER* ApiSetMap, _In_ const UNICODE_STRING* Namespace, _Out_ BOOLEAN* IsInSchema, _Out_ BOOLEAN* Present);

typedef NTSTATUS(__stdcall ApiSetQueryApiSetPresenceEx)(_In_ const UNICODE_STRING* Namespace, _Out_ BOOLEAN* IsInSchema, _Out_ BOOLEAN* Present); // Exported

typedef NTSTATUS(__stdcall ApiSetQueryApiSetPresence)(_In_ const UNICODE_STRING* ApiName, _Out_ bool* status); // Exported

typedef void(__fastcall LdrpInsertDataTableEntry)(_Inout_ DATA_TABLE_ENTRY* LdrEntry);

typedef NT_HEADERS* (__stdcall RtlImageNtHeader)(_In_ const void* DllBase);

typedef void(__fastcall RtlpInsertInvertedFunctionTableEntry)(_Reserved_ void* reserved, _In_ UINT DllBase, _In_ DWORD SEHandlerTable, _In_ UINT SizeOfImage, _In_ DWORD SEHandlerCount);

typedef int(__fastcall RtlRemoveInvertedFunctionTable)(_In_ DWORD DllBase);

typedef void(__fastcall RtlxRemoveInvertedFunctionTable)(_Reserved_ int reserved, _In_ DWORD DllBase);

typedef int(__fastcall RtlpRemoveInvertedFunctionTableEntry)(_Reserved_ int reserved, _In_ int HeaderIndex);

typedef NTSTATUS(__fastcall LdrpResolveForwarder)(_In_ const char* ForwarderStr, _Inout_ DATA_TABLE_ENTRY* DependencyLdrEntry, _Inout_ DATA_TABLE_ENTRY* ParentLdrEntry, _Out_ void** RedirectionStatus);

typedef void* (__fastcall LdrpFreeLoadContext)(_Inout_ LOAD_CONTEXT* LoadContext);

typedef DATA_TABLE_ENTRY* (__fastcall LdrpHandleReplacedModule)(_In_ const DATA_TABLE_ENTRY* ReplacedModule);

typedef void* (__fastcall LdrpFreeReplacedModule)(_Inout_ DATA_TABLE_ENTRY* ReplacedModule);