#include "memory.h"
#include "logger.h"
#include "process.h"
#include "tools.h"

using namespace logger;
using namespace process;
using namespace tools;

AllowLog memory::events::NtAllocateVirtualMemory(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted)
{
	typedef NTSTATUS
	(NTAPI* fNtAllocateVirtualMemory)(
		HANDLE ProcessHandle,
		VOID** BaseAddress,
		ULONG ZeroBits,
		ULONG* RegionSize,
		ULONG AllocationType,
		ULONG Protect);

	AllowLog result = AllowLog::ALLOW_BOTH;

	if (!IsExecuted)
	{
		return result;
	}
	else
	{
		HANDLE ProcessHandle = reinterpret_cast<HANDLE*>(Args[0]);
		VOID** BaseAddress = reinterpret_cast<VOID**>(Args[1]);
		ULONG* RegionSize = reinterpret_cast<ULONG*>(Args[3]);
		ULONG AllocationType = static_cast<ULONG>(Args[4]);
		ULONG Protect = static_cast<ULONG>(Args[5]);

		if (NT_ERROR(Regs->EAX) || !BaseAddress || !RegionSize)
		{
			return result;
		}

		const char* mask = "~$AllocateVirtualMemory <0x%x> (Handle: 0x%08x [Pid: 0x%04x, Image: \"%s\"], BaseAddress: 0x%08x, Size: 0x%08x, Allocation: 0x%08x ['%s'], Protection: 0x%08x ['%s']) => 0x%08x;\n";

		Process process(ProcessHandle);
		process.ReadProcessImagePath();

		LogTraceTime(
			Time,
			mask,
			Sys->m_Id,
			process.GetProcessHandle(),
			process.GetProcessId(),
			process.GetProcessImagePath(),
			*BaseAddress,
			*RegionSize,
			AllocationType,
			ConstMaskToString(AllocationType, memory::AllocationMasks).c_str(),
			Protect,
			ConstMaskToString(Protect, memory::ProtectionMasks).c_str(),
			Regs->EAX);

		return result;
	}
}

AllowLog memory::events::NtWow64AllocateVirtualMemory64(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted)
{
	typedef NTSTATUS
	(NTAPI* fNtWow64AllocateVirtualMemory64)(
		HANDLE ProcessHandle,
		VOID** BaseAddress,
		ULONG ZeroBits,
		ULONG Unknown,
		ULONG* AllocationType,
		ULONG RegionSize,
		ULONG Protect);

	AllowLog result = AllowLog::ALLOW_BOTH;

	if (!IsExecuted)
	{
		return result;
	}
	else
	{
		HANDLE ProcessHandle = reinterpret_cast<HANDLE*>(Args[0]);
		VOID** BaseAddress = reinterpret_cast<VOID**>(Args[1]);
		ULONG ZeroBits = static_cast<ULONG>(Args[2]);
		ULONG Unknown = static_cast<ULONG>(Args[3]);
		ULONG* AllocationType = reinterpret_cast<ULONG*>(Args[4]);
		ULONG RegionSize = static_cast<ULONG>(Args[5]);
		ULONG Protect = static_cast<ULONG>(Args[6]);

		if (NT_ERROR(Regs->EAX) || !BaseAddress || !AllocationType)
		{
			return result;
		}

		const char* mask = "~$AllocateVirtualMemory64 <0x%x> (Handle: 0x%08x [Pid: 0x%04x, Image: \"%s\"], BaseAddress: 0x%08x, Allocation: 0x%08x ['%s'], Size: 0x%08x, Protection: 0x%08x ['%s']) => 0x%08x;\n";

		Process process(ProcessHandle);
		process.ReadProcessImagePath();

		LogTraceTime(
			Time,
			mask,
			Sys->m_Id,
			process.GetProcessHandle(),
			process.GetProcessId(),
			process.GetProcessImagePath(),
			*BaseAddress,
			*AllocationType,
			ConstMaskToString(*AllocationType, memory::AllocationMasks).c_str(),
			RegionSize,
			Protect,
			ConstMaskToString(Protect, memory::ProtectionMasks).c_str(),
			Regs->EAX);

		return result;
	}
}

AllowLog memory::events::NtProtectVirtualMemory(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted)
{
	typedef NTSTATUS
	(NTAPI* fNtProtectVirtualMemory)(
		HANDLE ProcessHandle,
		VOID** BaseAddress,
		ULONG* NumberOfBytesToProtect,
		ULONG NewAccessProtection,
		ULONG* OldAccessProtection);

	AllowLog result = AllowLog::ALLOW_BOTH;

	if (!IsExecuted)
	{
		return result;
	}
	else
	{
		HANDLE ProcessHandle = reinterpret_cast<HANDLE*>(Args[0]);
		VOID** BaseAddress = reinterpret_cast<VOID**>(Args[1]);
		ULONG* NumberOfBytesToProtect = reinterpret_cast<ULONG*>(Args[2]);
		ULONG NewAccessProtection = static_cast<ULONG>(Args[3]);
		ULONG* OldAccessProtection = reinterpret_cast<ULONG*>(Args[4]);

		if (NT_ERROR(Regs->EAX) || !BaseAddress || !NumberOfBytesToProtect)
		{
			return result;
		}

		const char* mask = "~$ProtectVirtualMemory <0x%x> (Handle: 0x%08x [Pid: 0x%04x, Image: \"%s\"], BaseAddress: 0x%08x, Size: 0x%08x, Protection: 0x%08x ['%s'], OldProtection: 0x%08x ['%s']) => 0x%08x;\n";

		Process process(ProcessHandle);
		process.ReadProcessImagePath();

		LogTraceTime(
			Time,
			mask,
			Sys->m_Id,
			process.GetProcessHandle(),
			process.GetProcessId(),
			process.GetProcessImagePath(),
			*BaseAddress,
			*NumberOfBytesToProtect,
			NewAccessProtection,
			ConstMaskToString(NewAccessProtection, memory::ProtectionMasks).c_str(),
			*OldAccessProtection,
			ConstMaskToString(*OldAccessProtection, memory::ProtectionMasks).c_str(),
			Regs->EAX);

		return result;
	}
}

AllowLog memory::events::NtWriteVirtualMemory(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted)
{
	typedef NTSTATUS
	(NTAPI* fNtWriteVirtualMemory)(
		HANDLE ProcessHandle,
		VOID* BaseAddress,
		VOID* Buffer,
		ULONG NumberOfBytesToWrite,
		ULONG* NumberOfBytesWritten);

	AllowLog result = AllowLog::ALLOW_BOTH;

	if (!IsExecuted)
	{
		return result;
	}
	else
	{
		HANDLE ProcessHandle = reinterpret_cast<HANDLE*>(Args[0]);
		VOID* BaseAddress = reinterpret_cast<VOID*>(Args[1]);
		VOID* Buffer = reinterpret_cast<VOID*>(Args[2]);
		ULONG NumberOfBytesToWrite = static_cast<ULONG>(Args[3]);
		ULONG* NumberOfBytesWritten = reinterpret_cast<ULONG*>(Args[4]);

		if (NT_ERROR(Regs->EAX))
		{
			return result;
		}

		const char* mask = "~$WriteVirtualMemory <0x%x> (Handle: 0x%08x [Pid: 0x%04x, Image: \"%s\"], BaseAddress: 0x%08x, Buffer: 0x%08x [%s], Size: 0x%08x) => 0x%08x;\n";

		Process process(ProcessHandle);
		process.ReadProcessImagePath();

		LogTraceTime(
			Time,
			mask,
			Sys->m_Id,
			process.GetProcessHandle(),
			process.GetProcessId(),
			process.GetProcessImagePath(),
			BaseAddress,
			Buffer,
			HexBuffer(Buffer, NumberOfBytesToWrite).c_str(),
			NumberOfBytesToWrite,
			Regs->EAX);

		return result;
	}
}

AllowLog memory::events::NtReadVirtualMemory(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted)
{
	typedef NTSTATUS
	(NTAPI* fNtReadVirtualMemory)(
		HANDLE ProcessHandle,
		VOID* BaseAddress,
		VOID* Buffer,
		ULONG NumberOfBytesToRead,
		ULONG* NumberOfBytesReaded);

	AllowLog result = AllowLog::ALLOW_BOTH;

	if (!IsExecuted)
	{
		return result;
	}
	else
	{
		HANDLE ProcessHandle = reinterpret_cast<HANDLE*>(Args[0]);
		VOID* BaseAddress = reinterpret_cast<VOID*>(Args[1]);
		VOID* Buffer = reinterpret_cast<VOID*>(Args[2]);
		ULONG NumberOfBytesToRead = static_cast<ULONG>(Args[3]);
		ULONG* NumberOfBytesReaded = reinterpret_cast<ULONG*>(Args[4]);

		if (NT_ERROR(Regs->EAX))
		{
			return result;
		}

		const char* mask = "~$ReadVirtualMemory <0x%x> (Handle: 0x%08x [Pid: 0x%04x, Image: \"%s\"], BaseAddress: 0x%08x, Buffer: 0x%08x [%s], Size: 0x%08x) => 0x%08x;\n";

		Process process(ProcessHandle);
		process.ReadProcessImagePath();

		LogTraceTime(
			Time,
			mask,
			Sys->m_Id,
			process.GetProcessHandle(),
			process.GetProcessId(),
			process.GetProcessImagePath(),
			BaseAddress,
			Buffer,
			HexBuffer(Buffer, NumberOfBytesToRead).c_str(),
			NumberOfBytesToRead,
			Regs->EAX);

		return result;
	}
}