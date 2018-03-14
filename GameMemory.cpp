#include "GameMemory.h"
#ifdef VISTA
#define PSAPI_VERSION 1
#endif
#include <Psapi.h>
#include <string>

void PlaceJMP(BYTE *bt_DetourAddress, DWORD dw_FunctionAddress, DWORD dw_Size)
{
	DWORD dw_OldProtection, dw_Distance;
	VirtualProtect(bt_DetourAddress, dw_Size, PAGE_EXECUTE_READWRITE, &dw_OldProtection);
	dw_Distance = (DWORD)(dw_FunctionAddress - (DWORD)bt_DetourAddress) - 5;
	*bt_DetourAddress = 0xE9;
	*(DWORD*)(bt_DetourAddress + 0x1) = dw_Distance;
	for (DWORD i = 0x5; i < dw_Size; i++) *(bt_DetourAddress + i) = 0x90;
	VirtualProtect(bt_DetourAddress, dw_Size, dw_OldProtection, NULL);
	return;
}

uintptr_t FindMemoryPattern(HANDLE ModuleHandle, char* strpattern, int length)
{
	//Filter out junk and get a clean hex version of the signature
	unsigned char *signature = new unsigned char[length + 1];
	bool *skippable = new bool[length + 1];
	int signaturelength = 0;
	for (int byteoffset = 0; byteoffset < length - 1; byteoffset += 2)
	{
		char charhex[4]; //4 to keep sscanf happy
		*(short*)charhex = *(short*)&strpattern[byteoffset];
		if (charhex[0] != ' ')
		{
			if (charhex[0] == '?')
			{
				signature[signaturelength] = '?';
				skippable[signaturelength] = true;
			}
			else
			{
				//Convert ascii to hex
				charhex[2] = NULL; //add null terminator
				signature[signaturelength] = (unsigned char)std::stoul(charhex, nullptr, 16);

				//sscanf(charhex, "%x", &signature[signaturelength]);
				skippable[signaturelength] = false;
			}
			signaturelength++;
		}
	}
	//double timetakentofilter = QPCTime() - startfilter;

	//Search for the hex signature in memory
	int searchoffset = 0;
	int maxoffset = signaturelength - 1;

	MODULEINFO dllinfo;
	GetModuleInformation(GetCurrentProcess(), (HMODULE)ModuleHandle, &dllinfo, sizeof(MODULEINFO));
	DWORD endadr = (DWORD)ModuleHandle + dllinfo.SizeOfImage;
	DWORD adrafterfirstmatch = NULL;
	for (DWORD adr = (DWORD)ModuleHandle; adr < endadr; adr++)
	{
		if (skippable[searchoffset] || *(char*)adr == signature[searchoffset] || *(unsigned char*)adr == signature[searchoffset])
		{
			if (searchoffset == 0)
			{
				adrafterfirstmatch = adr + 1;
			}
			searchoffset++;
			if (searchoffset > maxoffset)
			{
				delete[] signature;
				delete[] skippable;
				return adr - maxoffset; //FOUND OFFSET!
			}
		}
		else if (adrafterfirstmatch)
		{
			adr = adrafterfirstmatch;
			searchoffset = 0;
			adrafterfirstmatch = NULL;
		}
	}

	delete[] signature;
	delete[] skippable;
	return NULL; //NOT FOUND!
}