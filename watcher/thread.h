#pragma once
#include "config.h"
#include <map>

using namespace cfg;

namespace thread
{
	extern std::map<ACCESS_MASK, const char*> AccessMasks;

	namespace events
	{
		AllowLog NtGetContextThread(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted);
		AllowLog NtSetContextThread(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted);
		AllowLog NtCreateThread(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted);
		AllowLog NtCreateThreadEx(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted);
	}
}