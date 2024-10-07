#pragma once
#include "pch.h"
#include "ntdll.h"

typedef NTSTATUS(__fastcall LdrpAllocatePlaceHolder)(UNICODE_STRING* DllPath, LDR_DLL_DATA* pDllData, ULONG Flags, INT LoadReason, LDR_DATA_TABLE_ENTRY* ParentEntry, LDR_DATA_TABLE_ENTRY** pLdrEntry, NTSTATUS* State);

typedef LONG(__stdcall RtlCompareUnicodeStrings)(_In_ PWSTR Str1, _In_ UINT Sz1, _In_ PWSTR Str2, _In_ UINT Sz2, _In_ bool CaseInsensitive); // Not the same as RtlCompareUnicodeString

typedef HOST_ENTRY* (__fastcall ApiSetpSearchForApiSetHost)(_In_ NAMESPACE_ENTRY* NsEntry, _In_ PWSTR HostName, _In_ UINT16 HostNameSz, _In_ NAMESPACE_HEADER* ApiSetMap);

typedef NAMESPACE_ENTRY* (__fastcall ApiSetpSearchForApiSet)(_In_ NAMESPACE_HEADER* ApiSetMap, _In_ PWSTR ApiName, _In_ UINT16 ApiSubNameSz);

typedef NTSTATUS(__fastcall ApiSetResolveToHost)(_In_ NAMESPACE_HEADER* ApiSetMap, _In_ UNICODE_STRING* ApiName, _In_opt_ UNICODE_STRING* ParentName, _Out_ bool* Resolved, _Out_ UNICODE_STRING* HostName);

typedef PWSTR(__stdcall RtlGetNtSystemRoot)(); // Exported

typedef NTSTATUS(__fastcall LdrpGetFullPath)(_In_ UNICODE_STRING* DllName, _Out_ UNICODE_STRING* DllPath);

typedef NTSTATUS(__fastcall LdrpPreprocessDllName)(_In_ UNICODE_STRING* DllName, _Out_ UNICODE_STRING* ProcessedName, _In_opt_ LDR_DATA_TABLE_ENTRY* ParentLdrEntry, _Inout_ ULONG* LoadFlags);

typedef NTSTATUS(__fastcall LdrpParseForwarderDescription)(_In_ char* Forwarder, _Out_ STRING* DllName, _Out_ char** ExportName, _In_ ULONG Ordinal);

typedef UINT(__stdcall LdrStandardizeSystemPath)(_Inout_ UNICODE_STRING* Path); // Exported

typedef NTSTATUS(__fastcall LdrpComputeLazyDllPath)(_Inout_ LDR_DLL_DATA* DllData);

typedef NTSTATUS(__fastcall LdrpMapDllRetry)(_Inout_ LOAD_CONTEXT* LoadContext);

typedef NTSTATUS(__fastcall LdrpMapDllFullPath)(_Inout_ LOAD_CONTEXT* LoadContext);

typedef NTSTATUS(__fastcall LdrpMapDllNtFileName)(_Inout_ LOAD_CONTEXT* LoadContext, _In_ UNICODE_STRING* ObjName);

typedef NTSTATUS(__fastcall LdrpMapDllWithSectionHandle)(_Inout_ LOAD_CONTEXT* LoadContext);

typedef ULONG(__fastcall LdrpHashUnicodeString)(_In_ UNICODE_STRING* Str);

typedef NTSTATUS(__fastcall LdrpCorProcessImports)(_Inout_ LDR_DATA_TABLE_ENTRY* LdrEntry);

typedef NTSTATUS* (__fastcall LdrpMapAndSnapDependency)(_Inout_ LOAD_CONTEXT* LoadContext);

typedef NTSTATUS(__fastcall LdrpPrepareImportAddressTableForSnap)(_Inout_ LOAD_CONTEXT* LoadContext);

typedef bool(__fastcall LdrpShouldModuleImportBeRedirected)(_In_ LDR_DATA_TABLE_ENTRY* LdrEntry);

typedef IMAGE_IMPORT_DESCRIPTOR* (__fastcall LdrpGetImportDescriptorForSnap)(_Inout_ LOAD_CONTEXT* LoadContext);

typedef NTSTATUS(__fastcall RtlpImageDirectoryEntryToDataEx)(_In_ void* Base, _In_ bool MappedAsImage, _In_ UINT16 DirectoryEntry, _Out_ ULONG* DirSize, _Out_ void** ResolvedAddress);

typedef NTSTATUS(__fastcall LdrpMapCleanModuleView)(_Inout_ LOAD_CONTEXT* LoadContext);

typedef NTSTATUS(__fastcall LdrpProcessWork)(_Inout_ LOAD_CONTEXT* LoadContext, _In_ bool IsLoadOwner);

typedef LDR_DATA_TABLE_ENTRY* (__fastcall LdrpHandleReplacedModule)(_Inout_ LDR_DATA_TABLE_ENTRY* LdrEntry);