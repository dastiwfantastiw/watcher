#pragma once
#include "config.h"
#include <map>
#include <winternl.h>

using namespace cfg;

namespace file
{
	extern std::map<ACCESS_MASK, const char*> AccessMasks;
	extern std::map<ACCESS_MASK, const char*> ShareAccessMasks;
	extern std::map<ACCESS_MASK, const char*> AttributesMasks;
	extern std::map<ACCESS_MASK, const char*> OpenMasks;

	namespace events
	{
		AllowLog NtCreateFile(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted);
		AllowLog NtReadFile(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted);
		AllowLog NtWriteFile(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted);
		AllowLog NtDeleteFile(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted);
		AllowLog NtDeviceIoControlFile(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted);
		AllowLog NtOpenFile(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted);
	}
}