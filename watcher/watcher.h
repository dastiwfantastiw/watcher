#pragma once
#include "config.h"
#include "database.h"

using namespace cfg;
using namespace sys_database;

namespace watcher
{
	extern HANDLE MapDllHandle;
	extern Config* Configuration;
	extern SysDataBase* SysDB;

	extern std::string LogFilePath;
	extern std::map<DWORD, Syscall::Event> SysEvents;

	int InitSyscalls();
	int InitSyscallsCumstomHandlers();

	void LogCurrentProcessInfo();

	bool AttachConfig(Config* Config);
	bool DebugAttachConfig();
	bool CreateLogFile();
	bool EnableSyscallHandler();

	bool SyscallHandler(DWORD Magic, DWORD Id, DWORD* Args, Registers* Regs);
}