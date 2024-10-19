#pragma once
#pragma comment(lib, "ntdll.lib")

#define WIN32_LEAN_AND_MEAN

#include <Windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <stdbool.h>
#include <stdio.h>