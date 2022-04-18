#pragma once
#include "config.h"

using namespace cfg;

namespace sys_hooker
{
	extern BYTE  MaxFrame;
	extern BYTE  GateBytes[7];
	extern BYTE  JumpBytes[7];
	extern BYTE  HandlerBytes[];
	extern BYTE* HandlerMemory;
	extern void* JumpMemoryPointer;

	bool IsMagicExistsInFrame(DWORD Ebp);
	bool InstallHook(void* Handler);
	bool ExecuteSyscall(DWORD Id, WORD Argc, DWORD* Args, Registers* Regs);
}