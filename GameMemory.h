#pragma once

#include <Windows.h>

void PlaceJMP(BYTE *bt_DetourAddress, DWORD dw_FunctionAddress, DWORD dw_Size);
uintptr_t FindMemoryPattern(HANDLE ModuleHandle, char* strpattern, int length);