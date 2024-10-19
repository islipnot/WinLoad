#pragma once

NTSTATUS ApiSetResolveToHost(const NAMESPACE_HEADER* ApiSetMap, const UNICODE_STRING* ApiName, const UNICODE_STRING* ParentName, bool* pResolved, UNICODE_STRING* HostName);