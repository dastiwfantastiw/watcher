#include "watcher.h"
#include "analyzer.h"
#include "logger.h"
#include "sys_hooker.h"
#include "tools.h"

#include "process.h"
#include "file.h"
#include "thread.h"
#include "section.h"
#include "memory.h"
#include "regkey.h"

using namespace analyzer;
using namespace logger;
using namespace sys_hooker;
using namespace tools;
using namespace process;
using namespace regkey;

namespace watcher
{
	HANDLE MapDllHandle = INVALID_HANDLE_VALUE;
	Config* Configuration = NULL;
	SysDataBase* SysDB = NULL;

	std::string LogFilePath;
	std::map<DWORD, Syscall::Event> SysEvents;
}

bool watcher::AttachConfig(Config* Config)
{
	if (!Config || 
		Config->m_Header.m_Magic != Magic || 
		Config->m_Header.m_Version != Version)
	{
		return false;
	}

	MaxFrame = Config->m_Settings.m_MaxFrame;
	MinStrLength = Config->m_Settings.m_MinStrLen;
	MaxStrLength = Config->m_Settings.m_MaxStrLen;
	MaxPtr = Config->m_Settings.m_MaxPtr;

	MapDllHandle = Config->m_Header.m_MappingHandle;
	Configuration = Config;

	if (Config->m_Settings.m_PathLength > 0)
	{
		LogFilePath = Config->m_Settings.m_Path;
	}

	return true;
}

bool watcher::CreateLogFile()
{
	std::string currProcessPath;
	currProcessPath.resize(MAX_PATH * 2);

	GetModuleFileNameA(NULL, const_cast<char*>(currProcessPath.c_str()), MAX_PATH);

	size_t delim = LogFilePath.find_last_of("/\\");

	std::string currProcessName = currProcessPath.substr(currProcessPath.find_last_of("/\\") + 1);
	currProcessName.resize(currProcessName.size() + 12);

	FormatString(const_cast<char*>(currProcessName.c_str()), currProcessName.size(), "%s_0x%04x.wtr", currProcessName.c_str(), GetCurrentProcessId());

	std::string userFileName = LogFilePath.substr(delim + 1);
	std::string userDirectory = LogFilePath.substr(NULL, delim + 1);

	if (currProcessName.empty())
	{
		currProcessName = currProcessName;
	}

	auto lambdaCreateFile = [](const char* fileName) -> HANDLE
	{
		return CreateFileA(fileName, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, NULL, NULL);
	};

	logger::hFile = lambdaCreateFile((userDirectory + userFileName).c_str());
	if (logger::hFile != INVALID_HANDLE_VALUE)
	{
		InitializeCriticalSection(&logger::critSect);
		LogFilePath = userDirectory + userFileName;
		return true;
	}

	logger::hFile = lambdaCreateFile((userDirectory + currProcessName).c_str());
	if (logger::hFile != INVALID_HANDLE_VALUE)
	{
		InitializeCriticalSection(&logger::critSect);
		LogFilePath = userDirectory + currProcessName;
		return true;
	}

	logger::hFile = lambdaCreateFile(currProcessName.c_str());
	if (logger::hFile != INVALID_HANDLE_VALUE)
	{
		InitializeCriticalSection(&logger::critSect);
		LogFilePath = currProcessName;
		return true;
	}

	return false;
}

int watcher::InitSyscalls()
{
	int count = NULL;

	if (Configuration &&
		Configuration->m_Settings.m_IsEnableSyscalls &&
		Configuration->m_Header.m_SyscallDllCount &&
		Configuration->m_Header.m_SyscallDllOffset)
	{
		if (!SysDB)
		{
			SysDB = new SysDataBase;
		}

		SyscallDllInfo* arrSysDllInfo = reinterpret_cast<SyscallDllInfo*>(reinterpret_cast<DWORD>(Configuration->m_Header.m_SyscallDllOffset) + reinterpret_cast<DWORD>(Configuration));

		for (size_t i = 0; i < Configuration->m_Header.m_SyscallDllCount; i++)
		{
			if (arrSysDllInfo[i].m_IsAllSyscalls || arrSysDllInfo[i].m_SyscallCount)
			{
				SysDataModule* sysModule = SysDB->AddModule(arrSysDllInfo[i]);
				if (sysModule)
				{
					BinSyscall* binSys = reinterpret_cast<BinSyscall*>(reinterpret_cast<DWORD>(arrSysDllInfo[i].m_Offset) + reinterpret_cast<DWORD>(Configuration));

					sysModule->UploadUnknownCalls(binSys, arrSysDllInfo[i].m_SyscallCount);
					sysModule->CheckModuleForUnknownCalls();
					count += sysModule->GetSizeKnownCalls();
				}
			}
		}
	}

	return count;
}

int watcher::InitSyscallsCumstomHandlers()
{
	return SysDB->InstallCustomHandlers(
		SysEvents =
		{
			{ 0x23500534, process::events::NtOpenProcess},
			{ 0x49ce0795, process::events::NtCreateUserProcess },
			{ 0x83420a3e, process::events::NtQueryInformationProcess },
			{ 0x6d8a0954, process::events::NtSetInformationProcess },
		    { 0x36760684, process::events::NtSuspendProcess },
		    { 0x2f7a0613, process::events::NtResumeProcess },
		    { 0x43f9074b, process::events::NtTerminateProcess },

			{ 0x42680720, thread::events::NtGetContextThread },
			{ 0x4328072c, thread::events::NtSetContextThread },
			{ 0x281b056f, thread::events::NtCreateThread },
			{ 0x33fb062c, thread::events::NtCreateThreadEx },

			{ 0x6c930948, memory::events::NtAllocateVirtualMemory },
			{ 0xaf070b59, memory::events::NtWow64AllocateVirtualMemory64 },
			{ 0x65f10904, memory::events::NtProtectVirtualMemory },
			{ 0x5450082e, memory::events::NtWriteVirtualMemory },
			{ 0x49e4079f, memory::events::NtReadVirtualMemory },

			{ 0x1d600497, file::events::NtCreateFile },
			{ 0x144703bf, file::events::NtReadFile },
			{ 0x19ac044e, file::events::NtWriteFile },
			{ 0x1d490496, file::events::NtDeleteFile },
			{ 0x586c082c, file::events::NtDeviceIoControlFile },
			{ 0x14c603d5, file::events::NtOpenFile },

			{ 0x2dfe05ec, section::events::NtCreateSection },
			{ 0x41080706, section::events::NtMapViewOfSection },
			{ 0x2868054a, section::events::NtOpenSection },
			{ 0x2eef0600, section::events::NtExtendSection },
			{ 0x51d607e9, section::events::NtUnmapViewOfSection },

			{ 0x18dd0440, regkey::events::NtCreateKey },
			{ 0x18c7043f, regkey::events::NtDeleteKey },
			{ 0x33f1063c, regkey::events::NtDeleteValueKey },
			{ 0x1105037e, regkey::events::NtOpenKey },
			{ 0x15850402, regkey::events::NtQueryKey },
			{ 0x2f7e05ff, regkey::events::NtQueryValueKey },
			{ 0x22ea0515, regkey::events::NtSetValueKey }
		});
}

void watcher::LogCurrentProcessInfo()
{
	if (logger::hFile != INVALID_HANDLE_VALUE && logger::hFile != NULL)
	{
		process::Process process(GetCurrentProcess());
		if (process.ReOpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ))
		{
			process.ReadProcessImagePath();
			process.ReadProcessCommandLine();

			DWORD parentPid = process.GetProcessParentId();

			logger::LogTrace(
				"$Pid: 0x%04x (%d)\n"
				"$Image: \"%s\"\n"
				"$CommandLine: \"%s\"\n\n",
				process.GetProcessId(), process.GetProcessId(),
				process.GetProcessImagePath(), process.GetProcessCommandLine());

			if (parentPid)
			{
				HANDLE hParentProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ, false, parentPid);
				if (hParentProcess != INVALID_HANDLE_VALUE)
				{
					process::Process parentProcess(hParentProcess);

					parentProcess.ReadProcessImagePath();
					parentProcess.ReadProcessCommandLine();

					logger::LogTrace(
						"$ParentPid: 0x%04x (%d)\n"
						"$ParentImage: \"%s\"\n"
						"$ParentCommandLine: \"%s\"\n\n",
						parentProcess.GetProcessId(), parentProcess.GetProcessId(),
						parentProcess.GetProcessImagePath(), parentProcess.GetProcessCommandLine());
					parentProcess.CloseHandle();
				}
			}
			process.CloseHandle();
		}
	}
}

bool watcher::EnableSyscallHandler()
{
	return sys_hooker::InstallHook(SyscallHandler);
}
