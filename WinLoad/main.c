#include "pch.h"
#include "ntdll.h"
#include "recreations.h"

void ListModules()
{
    LIST_ENTRY* ModuleListHead = &NtCurrentPeb()->Ldr->InLoadOrderModuleList;
    LOAD_ORDER_MODULE_LIST_ENTRY* ModuleList = (LOAD_ORDER_MODULE_LIST_ENTRY*)ModuleListHead->Flink;

    for (int i = 1; ModuleList->ListEntry.Flink != ModuleListHead; ++i)
    {
        const DATA_TABLE_ENTRY* LdrEntry = ModuleList->LdrEntry;

        printf("\n[+] MODULE #%d\n", i);
        printf("\n> LDR_DATA_TABLE_ENTRY\n\n");
        printf("- FullDllName: %wZ\n",    &LdrEntry->FullDllName);
        printf("- DllBase: 0x%X\n",       (UINT)LdrEntry->DllBase);
        printf("- ParentDllBase: 0x%X\n", (UINT)LdrEntry->ParentDllBase);

        ModuleList = (LOAD_ORDER_MODULE_LIST_ENTRY*)ModuleList->ListEntry.Flink;
    }
}

void ResolveApi(PWSTR api)
{
    UNICODE_STRING ApiName;
    ApiName.Buffer = api;
    ApiName.MaximumLength = ApiName.Length = (wcslen(api) - 1) << 1;

    bool resolved;
    UNICODE_STRING HostName;
    ApiSetResolveToHost(NtCurrentPeb()->ApiSetMap, &ApiName, NULL, &resolved, &HostName);

    printf("API Set: %ls\n", api);
    printf("Primary Host: %wZ\n", &HostName);
}

int wmain(int argc, WCHAR* argv[])
{
    // Checking argument(s)

    if (!_wcsicmp(argv[1], L"ModuleList"))
    {
        ListModules();
    }
    else if (!_wcsicmp(argv[1], L"ResolveApi"))
    {
        ResolveApi(argv[2]);
    }
    else printf("Invalid argument(s)\n");

    return 0;
}