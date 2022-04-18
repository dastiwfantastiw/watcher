#include "process.h"
#include "tools.h"
#include "memory.h"

using namespace memory;
using namespace tools;

namespace process
{
	std::map<ACCESS_MASK, const char*> AccessMasks =
	{
		{0x0001, "PROCESS_TERMINATE"},
		{0x0002, "PROCESS_CREATE_THREAD"},
		{0x0004, "PROCESS_SET_SESSIONID"},
		{0x0008, "PROCESS_VM_OPERATION"},
		{0x0010, "PROCESS_VM_READ"},
		{0x0020, "PROCESS_VM_WRITE"},
		{0x0040, "PROCESS_DUP_HANDLE"},
		{0x0080, "PROCESS_CREATE_PROCESS"},
		{0x0100, "PROCESS_SET_QUOTA"},
		{0x0200, "PROCESS_SET_INFORMATION"},
		{0x0400, "PROCESS_QUERY_INFORMATION"},
		{0x0800, "PROCESS_SUSPEND_RESUME"},
		{0x1000, "PROCESS_QUERY_LIMITED_INFORMATION"},
		{0x2000, "PROCESS_SET_LIMITED_INFORMATION"}
	};

	std::map<DWORD, const char*> ProcessInformationClassEnum =
	{
		 {0, "ProcessBasicInformation"},
		 {1, "ProcessQuotaLimits"},
		 {2, "ProcessIoCounters"},
		 {3, "ProcessVmCounters"},
		 {4, "ProcessTimes"},
		 {5, "ProcessBasePriority"},
		 {6, "ProcessRaisePriority"},
		 {7, "ProcessDebugPort"},
		 {8, "ProcessExceptionPort"},
		 {9, "ProcessAccessToken"},
		 {10, "ProcessLdtInformation"},
		 {11, "ProcessLdtSize"},
		 {12, "ProcessDefaultHardErrorMode"},
		 {13, "ProcessIoPortHandlers"},
		 {14, "ProcessPooledUsageAndLimits"},
		 {15, "ProcessWorkingSetWatch"},
		 {16, "ProcessUserModeIOPL"},
		 {17, "ProcessEnableAlignmentFaultFixup"},
		 {18, "ProcessPriorityClass"},
		 {19, "ProcessWx86Information"},
		 {20, "ProcessHandleCount"},
		 {21, "ProcessAffinityMask"},
		 {22, "ProcessPriorityBoost"},
		 {23, "ProcessDeviceMap"},
		 {24, "ProcessSessionInformation"},
		 {25, "ProcessForegroundInformation"},
		 {26, "ProcessWow64Information"},
		 {27, "ProcessImageFileName"},
		 {28, "ProcessLUIDDeviceMapsEnabled"},
		 {29, "ProcessBreakOnTermination"},
		 {30, "ProcessDebugObjectHandle"},
		 {31, "ProcessDebugFlags"},
		 {32, "ProcessHandleTracing"},
		 {33, "ProcessIoPriority"},
		 {34, "ProcessExecuteFlags"},
		 {35, "ProcessResourceManagement"},
		 {36, "ProcessCookie"},
		 {37, "ProcessImageInformation"},
		 {38, "ProcessCycleTime"},
		 {39, "ProcessPagePriority"},
		 {40, "ProcessInstrumentationCallback"},
		 {41, "ProcessThreadStackAllocation"},
		 {42, "ProcessWorkingSetWatchEx"},
		 {43, "ProcessImageFileNameWin32"},
		 {44, "ProcessImageFileMapping"},
		 {45, "ProcessAffinityUpdateMode"},
		 {46, "ProcessMemoryAllocationMode"},
		 {47, "ProcessGroupInformation"},
		 {48, "ProcessTokenVirtualizationEnabled"},
		 {49, "ProcessConsoleHostProcess"},
		 {50, "ProcessWindowInformation"},
		 {51, "ProcessHandleInformation"},
		 {52, "ProcessMitigationPolicy"},
		 {53, "ProcessDynamicFunctionTableInformation"},
		 {54, "ProcessHandleCheckingMode"},
		 {55, "ProcessKeepAliveCount"},
		 {56, "ProcessRevokeFileHandles"},
		 {57, "ProcessWorkingSetControl"},
		 {58, "ProcessHandleTable"},
		 {59, "ProcessCheckStackExtentsMode"},
		 {60, "ProcessCommandLineInformation"},
		 {61, "ProcessProtectionInformation"},
		 {62, "ProcessMemoryExhaustion"},
		 {63, "ProcessFaultInformation"},
		 {64, "ProcessTelemetryIdInformation"},
		 {65, "ProcessCommitReleaseInformation"},
		 {66, "ProcessDefaultCpuSetsInformation"},
		 {67, "ProcessAllowedCpuSetsInformation"},
		 {68, "ProcessReserved1Information"},
		 {69, "ProcessReserved2Information"},
		 {70, "ProcessSubsystemProcess"},
		 {71, "ProcessJobMemoryInformation"},
		 {72, "MaxProcessInfoClass"}
	};
}

process::Process::Process(HANDLE ProcessHandle)
{
	m_Handle = ProcessHandle;
	m_Id = ::GetProcessId(ProcessHandle);
	m_EnvironmentBlock = { 0 };
	m_BasicInfo = { 0 };
	m_Params = { 0 };

	m_ImagePath.clear();
	m_CommandLine.clear();
}

HANDLE process::Process::GetProcessHandle()
{
	return m_Handle;
}

DWORD process::Process::GetProcessId()
{
	return m_Id;
}

DWORD process::Process::GetProcessParentId()
{
	PROCESS_BASIC_INFORMATION pbi;
	if (NT_SUCCESS(QueryInformationProcess(m_Handle, tools::ProcessBasicInformation, &pbi, sizeof(pbi), NULL)))
	{
		return reinterpret_cast<DWORD>(pbi.Reserved3);
	}
	return NULL;
}

const char* process::Process::GetProcessImagePath()
{
	return m_ImagePath.c_str();
}

const char* process::Process::GetProcessCommandLine()
{
	return m_CommandLine.c_str();
}

PEB* process::Process::GetProcessEnvironmentBlock()
{
	return &m_EnvironmentBlock;
}

bool process::Process::CloseHandle()
{
	return ::CloseHandle(m_Handle);
}

bool process::Process::ReadProcessEnvironmentBlock()
{
	if (NT_SUCCESS(QueryInformationProcess(m_Handle, tools::ProcessBasicInformation, &m_BasicInfo, sizeof(m_BasicInfo), NULL)))
	{
		return ReadMemory(m_Handle, m_BasicInfo.PebBaseAddress, &m_EnvironmentBlock, sizeof(m_EnvironmentBlock));
	}
	return false;
}

bool process::Process::ReadProcessParameters()
{
	if (!m_EnvironmentBlock.ProcessParameters)
	{
		if (ReadProcessEnvironmentBlock())
		{
			return ReadProcessParameters();
		}
		return false;
	}

	return ReadMemory(m_Handle, m_EnvironmentBlock.ProcessParameters, &m_Params, sizeof(m_Params));
}

bool process::Process::ReadProcessImagePath()
{
	return process::GetProcessImagePath(m_Handle, m_ImagePath);
}

bool process::Process::ReadProcessCommandLine()
{
	return process::GetProcessCommandLine(m_Handle, m_CommandLine);
}

bool process::Process::ReOpenProcess(DWORD NewAccessRights)
{
	HANDLE hProcess = OpenProcess(NewAccessRights, false, m_Id);
	if (hProcess != INVALID_HANDLE_VALUE)
	{
		m_Handle = hProcess;
		m_Id = ::GetProcessId(m_Handle);
		m_EnvironmentBlock = { 0 };
		m_BasicInfo = { 0 };
		m_Params = { 0 };

		m_ImagePath.clear();
		m_CommandLine.clear();
		return true;
	}
	return false;
}

bool process::GetProcessImagePath(HANDLE ProcessHandle, std::string& Destination)
{
	DWORD needSize = NULL;
	NTSTATUS status = QueryInformationProcess(ProcessHandle, tools::ProcessImageFileNameWin32, NULL, NULL, &needSize);

	if (NT_SUCCESS(status) ||
		STATUS_INFO_LENGTH_MISMATCH == status)
	{
		std::vector<byte> buffer;
		buffer.resize(needSize);

		status = QueryInformationProcess(ProcessHandle, tools::ProcessImageFileNameWin32, buffer.data(), buffer.size(), NULL);

		if (NT_SUCCESS(status))
		{
			UNICODE_STRING* usBuffer = reinterpret_cast<UNICODE_STRING*>(buffer.data());

			if (usBuffer && usBuffer->Length)
			{
				Destination.resize(usBuffer->Length);
				return UnicodeToAscii(usBuffer->Buffer, Destination);
			}
		}
	}
	return false;
}

bool process::GetProcessCommandLine(HANDLE ProcessHandle, std::string& Destination)
{
	DWORD needSize = NULL;
	NTSTATUS status = QueryInformationProcess(ProcessHandle, tools::ProcessCommandLineInformation, NULL, NULL, &needSize);

	if (NT_SUCCESS(status) ||
		STATUS_INFO_LENGTH_MISMATCH == status)
	{
		std::vector<byte> buffer;
		buffer.resize(needSize);

		status = QueryInformationProcess(ProcessHandle, tools::ProcessCommandLineInformation, buffer.data(), buffer.size(), NULL);

		if (NT_SUCCESS(status))
		{
			UNICODE_STRING* usBuffer = reinterpret_cast<UNICODE_STRING*>(buffer.data());

			if (usBuffer && usBuffer->Length)
			{
				Destination.resize(usBuffer->Length);
				return UnicodeToAscii(usBuffer->Buffer, Destination);
			}
		}
	}
	return false;
}

bool process::GetProcessImagePath(DWORD ProcessId, std::string& Destination)
{
	HANDLE ProcessHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, ProcessId);
	if (ProcessHandle != INVALID_HANDLE_VALUE)
	{
		bool result = GetProcessImagePath(ProcessHandle, Destination);
		CloseHandle(ProcessHandle);
		return result;
	}
	return false;
}

bool process::GetProcessCommandLine(DWORD ProcessId, std::string& Destination)
{
	HANDLE ProcessHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, ProcessId);
	if (ProcessHandle != INVALID_HANDLE_VALUE)
	{
		bool result = GetProcessCommandLine(ProcessHandle, Destination);
		CloseHandle(ProcessHandle);
		return result;
	}
	return false;
}