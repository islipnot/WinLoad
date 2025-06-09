#include "pch.h"
#include "ntdll.h"
#include "recreations.h"

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
    if (argc < 2)
    {
        printf("ERROR: No API name provided for resolution\n");
        return 1;
    }

    ResolveApi(argv[1]);

    return 0;
}