#include <iostream>
#include "GameMemory.h"

DWORD RunCmdJMPBackAddress;
DWORD AnimstateUpdateJMPBackAddress;
DWORD MoveHelperServer;
int NumCommandsToRun;

//CBasePlayer::PhysicsSimulate -> RunCommand
__declspec(naked) void OnRunCommand()
{
	__asm {
		mov NumCommandsToRun, edi //store number of commands left to run
		mov eax, MoveHelperServer
		push[eax]
		jmp RunCmdJMPBackAddress
	}
}

//CCSGOPlayerAnimState::Update
__declspec(naked) void AnimStateUpdate()
{
	__asm {
		cmp byte ptr ss : [ebp + 0x8], 0 //if argument to CCSGOPlayerAnimState::Update says to force update, then do it
		jne update
		cmp NumCommandsToRun, 1 //if the number of usercmds left to run is more than 1 then don't update animations
		jg dontupdateyet
		update :
		movss xmm1, [ecx + 0x10] //run code that we overwrote when detour hooking
		jmp AnimstateUpdateJMPBackAddress //return and update the animations

		dontupdateyet : //don't update animations
		pop edi
		pop esi
		mov esp, ebp
		pop ebp
		retn 4
	}
}

void Hook()
{
	HMODULE serverhandle = NULL;
	while (!serverhandle)
	{
		serverhandle = GetModuleHandleA("server.dll");
		Sleep(50);
	}

	printf("Hooking CBasePlayer::PhysicsSimulate..\n");
	char *physicssimulateruncommandloopsig = "FF  35  ??  ??  ??  ??  8B  06  8B  CE  53";
	DWORD adr = FindMemoryPattern(serverhandle, physicssimulateruncommandloopsig, strlen(physicssimulateruncommandloopsig));
	
	if (!adr)
	{
		printf("ERROR: CAN'T FIND CBasePlayer::PhysicsSimulate SIGNATURE, EXITING!\n");
		Sleep(5000);
		exit(EXIT_SUCCESS);
	}

	RunCmdJMPBackAddress = (adr + 6);
	MoveHelperServer = *(DWORD*)(adr + 2);
	PlaceJMP((BYTE*)adr, (DWORD)&OnRunCommand, 6);

	printf("Hooking CCSGOPlayerAnimState::Update..\n");
	char *animstateupdatesig = "F3  0F  10  49  10  F3  0F  5C  4F  5C";
	adr = FindMemoryPattern(serverhandle, animstateupdatesig, strlen(animstateupdatesig));

	if (!adr)
	{
		printf("ERROR: CAN'T FIND CCSGOPlayerAnimState::Update SIGNATURE, EXITING!\n");
		Sleep(5000);
		exit(EXIT_SUCCESS);
	}

	AnimstateUpdateJMPBackAddress = (adr + 5);
	PlaceJMP((BYTE*)adr, (DWORD)&AnimStateUpdate, 5);
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
		case DLL_PROCESS_ATTACH:
		{
	#if debugmode
			AllocConsole();
			FILE* fp;
			freopen_s(&fp, "CONOUT$", "w", stdout);
	#endif
			std::cout << "Mutiny Fake Angle Fix Injected" << std::endl;

			break;
		}
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
		case DLL_PROCESS_DETACH:
			break;
	}
	return TRUE;
}