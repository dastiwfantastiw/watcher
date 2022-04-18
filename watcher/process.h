#pragma once
#include "config.h"
#include <ntstatus.h>
#include <winternl.h>
#include <map>
#include <vector>

#undef GetCommandLine

using namespace cfg;

namespace process
{
	typedef struct _CURDIR
	{
		UNICODE_STRING DosPath;
		PVOID Handle;
	} CURDIR, * PCURDIR;

	typedef struct _RTL_USER_PROCESS_PARAMETERS
	{
		ULONG MaximumLength;
		ULONG Length;
		ULONG Flags;
		ULONG DebugFlags;
		PVOID ConsoleHandle;
		ULONG ConsoleFlags;
		PVOID StandardInput;
		PVOID StandardOutput;
		PVOID StandardError;
		CURDIR CurrentDirectory;
		UNICODE_STRING DllPath;
		UNICODE_STRING ImagePathName;
		UNICODE_STRING CommandLine;
		PVOID Environment;
		ULONG StartingX;
		ULONG StartingY;
		ULONG CountX;
		ULONG CountY;
		ULONG CountCharsX;
		ULONG CountCharsY;
		ULONG FillAttribute;
		ULONG WindowFlags;
		ULONG ShowWindowFlags;
		UNICODE_STRING WindowTitle;
		UNICODE_STRING DesktopInfo;
		UNICODE_STRING ShellInfo;
		UNICODE_STRING RuntimeData;
	} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

	class Process
	{
	private:
		HANDLE                      m_Handle;
		DWORD                       m_Id;

		PEB                         m_EnvironmentBlock;
		PROCESS_BASIC_INFORMATION   m_BasicInfo;
		RTL_USER_PROCESS_PARAMETERS m_Params;

		std::string                 m_ImagePath;
		std::string                 m_CommandLine;

	public:
		Process(HANDLE ProcessHandle);

		HANDLE GetProcessHandle();

		DWORD GetProcessId();
		DWORD GetProcessParentId();

		const char* GetProcessImagePath();
		const char* GetProcessCommandLine();

		PEB* GetProcessEnvironmentBlock();

		bool CloseHandle();
		bool ReadProcessEnvironmentBlock();
		bool ReadProcessParameters();
		bool ReadProcessImagePath();
		bool ReadProcessCommandLine();
		bool ReOpenProcess(DWORD NewAccessRights);
	};

	bool GetProcessImagePath(HANDLE ProcessHandle, std::string& Destination);
	bool GetProcessCommandLine(HANDLE ProcessHandle, std::string& Destination);

	bool GetProcessImagePath(DWORD ProcessId, std::string& Destination);
	bool GetProcessCommandLine(DWORD ProcessId, std::string& Destination);

	extern std::map<ACCESS_MASK, const char*> AccessMasks;
	extern std::map<DWORD, const char*> ProcessInformationClassEnum;

	namespace events
	{
		AllowLog NtOpenProcess(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted);
		AllowLog NtCreateUserProcess(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted);
		AllowLog NtQueryInformationProcess(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted);
		AllowLog NtSetInformationProcess(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted);
		AllowLog NtSuspendProcess(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted);
		AllowLog NtResumeProcess(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted);
		AllowLog NtTerminateProcess(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted);
	}
}