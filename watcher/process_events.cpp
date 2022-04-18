#include "process.h"
#include "watcher.h"
#include "migrate.h"
#include "logger.h"
#include "tools.h"

using namespace migrate;
using namespace logger;
using namespace tools;

AllowLog process::events::NtOpenProcess(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted)
{
	typedef void CLIENT_ID, * PCLIENT_ID;

	typedef NTSTATUS
	(NTAPI* fNtOpenProcess)(
		HANDLE* ProcessHandle,
		ACCESS_MASK AccessMask,
		OBJECT_ATTRIBUTES* ObjectAttributes,
		PCLIENT_ID ClientId);

	AllowLog result = AllowLog::ALLOW_BOTH;
	if (!IsExecuted)
	{
		return result;
	}
	else
	{
		HANDLE* ProcessHandle = reinterpret_cast<HANDLE*>(Args[0]);
		ACCESS_MASK AccessMask = static_cast<ACCESS_MASK>(Args[1]);

		if (NT_ERROR(Regs->EAX))
		{
			return result;
		}

		const char* mask = "~$OpenProcess <0x%x> (Handle: 0x%08x [Pid: 0x%04x, Image: \"%s\"], Access: 0x%08x ['%s']) => 0x%08x;\n";

		Process process(*ProcessHandle);
		process.ReadProcessImagePath();

		LogTraceTime(
			Time,
			mask,
			Sys->m_Id,
			process.GetProcessHandle(),
			process.GetProcessId(),
			process.GetProcessImagePath(),
			AccessMask,
			ConstMaskToString(AccessMask, process::AccessMasks).c_str(),
			Regs->EAX);

		return result;
	}
}

AllowLog process::events::NtCreateUserProcess(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted)
{
	typedef void PROCESS_CREATE_INFO, * PPROCESS_CREATE_INFO;
	typedef void PROCESS_ATTRIBUTE_LIST, * PPROCESS_ATTRIBUTE_LIST;

	typedef NTSTATUS
	(NTAPI* fNtCreateUserProcess)(
		HANDLE* ProcessHandle,
		HANDLE* ThreadHandle,
		ACCESS_MASK ProcessDesiredAccess,
		ACCESS_MASK ThreadDesiredAccess,
		OBJECT_ATTRIBUTES* ProcessObjectAttributes,
		OBJECT_ATTRIBUTES* ThreadObjectAttributes,
		ULONG ProcessFlags,
		ULONG ThreadFlags,
		process::RTL_USER_PROCESS_PARAMETERS* ProcessParameters,
		PROCESS_CREATE_INFO* CreateInfo,
		PPROCESS_ATTRIBUTE_LIST AttributeList);

	AllowLog result = AllowLog::ALLOW_BOTH;

	if (!IsExecuted)
	{
		return result;
	}
	else
	{
		HANDLE* ProcessHandle = reinterpret_cast<HANDLE*>(Args[0]);
		HANDLE* ThreadHandle = reinterpret_cast<HANDLE*>(Args[1]);
		process::RTL_USER_PROCESS_PARAMETERS* ProcessParameters = reinterpret_cast<process::RTL_USER_PROCESS_PARAMETERS*>(Args[8]);

		if (NT_ERROR(Regs->EAX) || !ProcessHandle || !ThreadHandle)
		{
			return result;
		}

		std::string imagePath, cmdLine;

		UnicodeToAscii(ProcessParameters->ImagePathName.Buffer, imagePath);
		UnicodeToAscii(ProcessParameters->CommandLine.Buffer, cmdLine);

		DWORD pid = GetProcessId(*ProcessHandle);
		DWORD tid = GetThreadId(*ThreadHandle);

		SYSTEMTIME st1;
		GetLocalTime(&st1);

		MigrateResult mgResult;
		if (Migrate(pid, tid, watcher::MapDllHandle, watcher::Configuration, mgResult))
		{
			LogTraceTime(st1, "; Migrated to the process %s (0x%04x)\n", imagePath.c_str(), pid);
		}
		else
		{
			LogTraceTime(st1, "; Migration to the process %s (0x%04x) failed due to \"%s\" (0x%08x)\n", imagePath.c_str(), pid, mgResult.m_Message.c_str(), mgResult.m_LastError);
		}

		const char* mask = "~$CreateProcess <0x%x> (Handle: 0x%08x [Pid: 0x%04x, Image: \"%s\", CmdLine: \"%s\"], Handle: 0x%08x [Tid: 0x%04x]) => 0x%08x;\n";

		LogTraceTime(
			Time,
			mask,
			Sys->m_Id,
			*ProcessHandle,
			GetProcessId(*ProcessHandle),
			imagePath.c_str(),
			cmdLine.c_str(),
			*ThreadHandle,
			GetThreadId(*ThreadHandle),
			Regs->EAX);

		return result;
	}
}

AllowLog process::events::NtQueryInformationProcess(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted)
{
	typedef void PROCESS_CREATE_INFO, * PPROCESS_CREATE_INFO;
	typedef void PROCESS_ATTRIBUTE_LIST, * PPROCESS_ATTRIBUTE_LIST;

	typedef NTSTATUS
	(NTAPI* fNtQueryInformationProcess)(
		HANDLE ProcessHandle,
		PROCESS_INFORMATION_CLASS ProcessInformationClass,
		VOID* ProcessInformation,
		ULONG ProcessInformationLength,
		ULONG* ReturnLength);

	AllowLog result = AllowLog::ALLOW_BOTH;

	if (!IsExecuted)
	{
		return result;
	}
	else
	{
		HANDLE ProcessHandle = reinterpret_cast<HANDLE>(Args[0]);
		PROCESS_INFORMATION_CLASS ProcessInformationClass = static_cast<PROCESS_INFORMATION_CLASS>(Args[1]);
		VOID* ProcessInformation = reinterpret_cast<VOID*>(Args[2]);
		ULONG ProcessInformationLength = static_cast<ULONG>(Args[3]);
		ULONG* ReturnLength = reinterpret_cast<ULONG*>(Args[4]);

		if (NT_ERROR(Regs->EAX))
		{
			return result;
		}

		const char* mask = "~$QueryInformationProcess <0x%x> (Handle: 0x%08x [Pid: 0x%04x, Image: \"%s\"], ProcessInformationClass: 0x%08x ['%s'], Buffer: 0x%08x, Size: 0x%08x) => 0x%08x;\n";

		Process process(ProcessHandle);
		process.ReadProcessImagePath();

		LogTraceTime(
			Time,
			mask,
			Sys->m_Id,
			process.GetProcessHandle(),
			process.GetProcessId(),
			process.GetProcessImagePath(),
			ProcessInformationClass,
			ConstToString(ProcessInformationClass, process::ProcessInformationClassEnum).c_str(),
			ProcessInformation,
			ProcessInformationLength,
			Regs->EAX);

		return result;
	}
}

AllowLog process::events::NtSetInformationProcess(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted)
{
	typedef void PROCESS_CREATE_INFO, * PPROCESS_CREATE_INFO;
	typedef void PROCESS_ATTRIBUTE_LIST, * PPROCESS_ATTRIBUTE_LIST;

	typedef NTSTATUS
	(NTAPI* fNtSetInformationProcess)(
		HANDLE ProcessHandle,
		PROCESS_INFORMATION_CLASS ProcessInformationClass,
		VOID* ProcessInformation,
		ULONG ProcessInformationLength);

	AllowLog result = AllowLog::ALLOW_BOTH;

	if (!IsExecuted)
	{
		return result;
	}
	else
	{
		HANDLE ProcessHandle = reinterpret_cast<HANDLE>(Args[0]);
		PROCESS_INFORMATION_CLASS ProcessInformationClass = static_cast<PROCESS_INFORMATION_CLASS>(Args[1]);
		VOID* ProcessInformation = reinterpret_cast<VOID*>(Args[2]);
		ULONG ProcessInformationLength = static_cast<ULONG>(Args[3]);

		if (NT_ERROR(Regs->EAX))
		{
			return result;
		}

		const char* mask = "~$SetInformationProcess <0x%x> (Handle: 0x%08x [Pid: 0x%04x, Image: \"%s\"], ProcessInformationClass: 0x%08x ['%s'], Buffer: 0x%08x, Size: 0x%08x) => 0x%08x;\n";

		Process process(ProcessHandle);
		process.ReadProcessImagePath();

		LogTraceTime(
			Time,
			mask,
			Sys->m_Id,
			process.GetProcessHandle(),
			process.GetProcessId(),
			process.GetProcessImagePath(),
			ProcessInformationClass,
			ConstToString(ProcessInformationClass, process::ProcessInformationClassEnum).c_str(),
			ProcessInformation,
			ProcessInformationLength,
			Regs->EAX);

		return result;
	}
}

AllowLog process::events::NtSuspendProcess(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted)
{
	typedef NTSTATUS
	(NTAPI* fNtSuspendProcess)(
		HANDLE ProcessHandle);

	AllowLog result = AllowLog::ALLOW_BOTH;

	if (!IsExecuted)
	{
		return result;
	}
	else
	{
		HANDLE ProcessHandle = reinterpret_cast<HANDLE>(Args[0]);

		if (NT_ERROR(Regs->EAX))
		{
			return result;
		}

		const char* mask = "~$SuspendProcess <0x%x> (Handle: 0x%08x [Pid: 0x%04x, Image: \"%s\"]) => 0x%08x;\n";

		Process process(ProcessHandle);
		process.ReadProcessImagePath();

		LogTraceTime(
			Time,
			mask,
			Sys->m_Id,
			process.GetProcessHandle(),
			process.GetProcessId(),
			process.GetProcessImagePath(),
			Regs->EAX);

		return result;
	}
}

AllowLog process::events::NtResumeProcess(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted)
{
	typedef NTSTATUS
	(NTAPI* fNtResumeProcess)(
		HANDLE ProcessHandle);

	AllowLog result = AllowLog::ALLOW_BOTH;

	if (!IsExecuted)
	{
		return result;
	}
	else
	{
		HANDLE ProcessHandle = reinterpret_cast<HANDLE>(Args[0]);

		if (NT_ERROR(Regs->EAX))
		{
			return result;
		}

		const char* mask = "~$ResumeProcess <0x%x> (Handle: 0x%08x [Pid: 0x%04x, Image: \"%s\"]) => 0x%08x;\n";

		Process process(ProcessHandle);
		process.ReadProcessImagePath();

		LogTraceTime(
			Time,
			mask,
			Sys->m_Id,
			process.GetProcessHandle(),
			process.GetProcessId(),
			process.GetProcessImagePath(),
			Regs->EAX);

		return result;
	}
}

AllowLog process::events::NtTerminateProcess(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted)
{
	typedef NTSTATUS
	(NTAPI* fNtTerminateProcess)(
		HANDLE ProcessHandle,
		NTSTATUS ExitStatus);

	AllowLog result = AllowLog::ALLOW_BOTH;

	if (!IsExecuted)
	{
		HANDLE ProcessHandle = reinterpret_cast<HANDLE>(Args[0]);
		NTSTATUS ExitStatus = static_cast<NTSTATUS>(Args[1]);

		const char* mask = "$TerminateProcess <0x%x> (Handle: 0x%08x [Pid: 0x%04x, Image: \"%s\"], ExitCode: 0x%08x);\n";

		Process process(ProcessHandle);
		process.ReadProcessImagePath();

		LogTraceTime(
			Time,
			mask,
			Sys->m_Id,
			process.GetProcessHandle(),
			process.GetProcessId(),
			process.GetProcessImagePath(),
			ExitStatus);

		return result;
	}
	else
	{
		HANDLE ProcessHandle = reinterpret_cast<HANDLE>(Args[0]);
		NTSTATUS ExitStatus = static_cast<NTSTATUS>(Args[1]);

		if (NT_ERROR(Regs->EAX))
		{
			return result;
		}

		const char* mask = "~$TerminateProcess <0x%x> (Handle: 0x%08x [Pid: 0x%04x, Image: \"%s\"], ExitCode: 0x%08x) => 0x%08x;\n";

		Process process(ProcessHandle);
		process.ReadProcessImagePath();

		LogTraceTime(
			Time,
			mask,
			Sys->m_Id,
			process.GetProcessHandle(),
			process.GetProcessId(),
			process.GetProcessImagePath(),
			ExitStatus,
			Regs->EAX);

		return result;
	}
}