#pragma once
#include "config.h"
#include <map>

using namespace cfg;

namespace section
{
	extern std::map<ACCESS_MASK, const char*> AccessMasks;
	extern std::map<ACCESS_MASK, const char*> AttributesMasks;

	namespace events
	{
		AllowLog NtCreateSection(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted);
		AllowLog NtMapViewOfSection(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted);
		AllowLog NtOpenSection(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted);
		AllowLog NtExtendSection(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted);
		AllowLog NtUnmapViewOfSection(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted);
	}
}