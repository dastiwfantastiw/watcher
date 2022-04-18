#include "watcher.h"
#include "memory.h"
#include "pe_format.h"
#include "logger.h"
#include "sys_hooker.h"

using namespace memory;
using namespace pe_format;
using namespace logger;
using namespace sys_hooker;

bool watcher::SyscallHandler(DWORD Magic, DWORD Id, DWORD* Args, Registers* Regs) //main syscall handler
{
	SYSTEMTIME st;
	GetLocalTime(&st);

	BOOLEAN IsExecuted = false;
	AllowLog logAllow = AllowLog::ALLOW_BOTH;

	if (SysDB)
	{
		PEFormat* sysModule = NULL;
		Syscall* syscall = SysDB->FindKnownCallIdInModules(Id, sysModule);

		if (!syscall || 
			(static_cast<WORD>(syscall->m_Flags) & static_cast<WORD>(Flag::ENABLED)) == 0)
		{
			return IsExecuted;
		}

		if (syscall->m_Event &&
			(static_cast<WORD>(syscall->m_Flags) & static_cast<WORD>(Flag::EVENT_ENABLED)) &&
			(static_cast<WORD>(syscall->m_Flags) & static_cast<WORD>(Flag::EVENT_LOG_BEFORE)))
		{
			logAllow = syscall->m_Event(st, syscall, Args, Regs, IsExecuted);
		}

		if (!IsExecuted &&
			(static_cast<WORD>(syscall->m_Flags) & static_cast<WORD>(Flag::ENABLED)) &&
			(static_cast<WORD>(syscall->m_Flags) & static_cast<WORD>(Flag::LOG_BEFORE)))
		{
			char* argsBuffer = LogAddAnalyzeArgsToBuffer(Args, syscall->m_Argc, syscall->m_Types);
			if (argsBuffer)
			{
				LogSysBeforeExec(st, syscall, argsBuffer, sysModule);
				Free(argsBuffer);
			}
		}

		if (!IsExecuted)
		{
			GetLocalTime(&st);
			IsExecuted = ExecuteSyscall(Id, syscall->m_Argc, Args, Regs);
		}

		if (syscall->m_Event &&
			(static_cast<WORD>(syscall->m_Flags) & static_cast<WORD>(Flag::EVENT_ENABLED)) &&
			(static_cast<WORD>(syscall->m_Flags) & static_cast<WORD>(Flag::EVENT_LOG_AFTER)))
		{
			logAllow = syscall->m_Event(st, syscall, Args, Regs, IsExecuted);
		}

		if (IsExecuted &&
			(static_cast<WORD>(syscall->m_Flags) & static_cast<WORD>(Flag::ENABLED)) &&
			(static_cast<WORD>(syscall->m_Flags) & static_cast<WORD>(Flag::LOG_AFTER)))
		{
			char* argsBuffer = LogAddAnalyzeArgsToBuffer(Args, syscall->m_Argc, syscall->m_Types);
			if (argsBuffer)
			{
				LogSysAfterExec(st, syscall, argsBuffer, sysModule, Regs->EAX);
				Free(argsBuffer);
			}
		}
	}

	return IsExecuted;
}