#pragma once
#include "pch.h"

// Invalid bits for dwFlags in LoadLibrary
#define LOAD_LIBRARY_INVALID_BITS 0xFFFF000

// Invalid flag combo for dwFlags in LoadLibrary
#define LOAD_LIBRARY_DATAFILE_BOTH LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE