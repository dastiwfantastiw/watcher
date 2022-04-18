#include "thread.h"
#include "logger.h"
#include "process.h"
#include "tools.h"

using namespace logger;
using namespace process;
using namespace tools;

AllowLog thread::events::NtGetContextThread(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted)
{
	typedef NTSTATUS
	(NTAPI* fNtGetContextThread)(
		HANDLE ThreadHandle,
		CONTEXT* Context);

	AllowLog result = AllowLog::ALLOW_BOTH;

	if (!IsExecuted)
	{
		return result;
	}
	else
	{
		HANDLE ThreadHandle = reinterpret_cast<HANDLE>(Args[0]);
		CONTEXT* Context = reinterpret_cast<CONTEXT*>(Args[1]);

		if (NT_ERROR(Regs->EAX) || !Context)
		{
			return result;
		}

		const char* mask =
			"~$GetContextThread <0x%x> (Handle: 0x%08x [Tid: 0x%04x], Context: 0x%08x ["
			"Eax = 0x%08x, "
			"Ebx = 0x%08x, "
			"Ecx = 0x%08x, "
			"Edx = 0x%08x, "
			"Esi = 0x%08x, "
			"Edi = 0x%08x, "
			"Esp = 0x%08x, "
			"Ebp = 0x%08x, "
			"Eip = 0x%08x]) => 0x%08x; \n";

		LogTraceTime(
			Time,
			mask,
			Sys->m_Id,
			ThreadHandle,
			GetThreadId(ThreadHandle),
			Context,
			Context->Eax,
			Context->Ebx,
			Context->Ecx,
			Context->Edx,
			Context->Esi,
			Context->Edi,
			Context->Esp,
			Context->Ebp,
			Context->Eip,
			Regs->EAX);

		return result;
	}
}

AllowLog thread::events::NtSetContextThread(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted)
{
	typedef NTSTATUS
	(NTAPI* fNtSetContextThread)(
		HANDLE ThreadHandle,
		CONTEXT* Context);

	AllowLog result = AllowLog::ALLOW_BOTH;

	if (!IsExecuted)
	{
		return result;
	}
	else
	{
		HANDLE ThreadHandle = reinterpret_cast<HANDLE>(Args[0]);
		CONTEXT* Context = reinterpret_cast<CONTEXT*>(Args[1]);

		if (NT_ERROR(Regs->EAX) || !Context)
		{
			return result;
		}

		const char* mask =
			"~$SetContextThread <0x%x> (Handle: 0x%08x [Tid: 0x%04x], Context: 0x%08x ["
			"Eax = 0x%08x, "
			"Ebx = 0x%08x, "
			"Ecx = 0x%08x, "
			"Edx = 0x%08x, "
			"Esi = 0x%08x, "
			"Edi = 0x%08x, "
			"Esp = 0x%08x, "
			"Ebp = 0x%08x, "
			"Eip = 0x%08x]) => 0x%08x; \n";

		LogTraceTime(
			Time,
			mask,
			Sys->m_Id,
			ThreadHandle,
			GetThreadId(ThreadHandle),
			Context,
			Context->Eax,
			Context->Ebx,
			Context->Ecx,
			Context->Edx,
			Context->Esi,
			Context->Edi,
			Context->Esp,
			Context->Ebp,
			Context->Eip,
			Regs->EAX);

		return result;
	}
}

AllowLog thread::events::NtCreateThread(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted)
{
	typedef NTSTATUS
	(NTAPI* fNtCreateThread)(
		HANDLE* ThreadHandle,
		ACCESS_MASK DesiredAccess,
		OBJECT_ATTRIBUTES* ObjectAttributes,
		HANDLE ProcessHandle,
		CLIENT_ID* ClientId,
		CONTEXT* ThreadContext,
		INITIAL_TEB* InitialTeb,
		BOOLEAN CreateSuspended);

	AllowLog result = AllowLog::ALLOW_BOTH;

	if (!IsExecuted)
	{
		return result;
	}
	else
	{
		HANDLE* ThreadHandle = reinterpret_cast<HANDLE*>(Args[0]);
		ACCESS_MASK DesiredAccess = static_cast<ACCESS_MASK>(Args[1]);
		OBJECT_ATTRIBUTES* ObjectAttributes = reinterpret_cast<OBJECT_ATTRIBUTES*>(Args[2]);
		HANDLE ProcessHandle = reinterpret_cast<HANDLE>(Args[3]);
		CLIENT_ID* ClientId = reinterpret_cast<CLIENT_ID*>(Args[4]);
		CONTEXT* ThreadContext = reinterpret_cast<CONTEXT*>(Args[5]);
		INITIAL_TEB* InitialTeb = reinterpret_cast<INITIAL_TEB*>(Args[6]);
		BOOLEAN CreateSuspended = static_cast<BOOLEAN>(Args[7]);

		if (NT_ERROR(Regs->EAX) || !ThreadHandle || !ThreadContext || !InitialTeb)
		{
			return result;
		}

		const char* mask =
			"~$CreateThread <0x%x> (Handle: 0x%08x [Tid: 0x%04x], Handle: 0x%08x [Pid: 0x%04x, Image: \"%s\"], Access: 0x%08x ['%s'], Context: 0x%08x ["
			"Eax = 0x%08x, "
			"Ebx = 0x%08x, "
			"Ecx = 0x%08x, "
			"Edx = 0x%08x, "
			"Esi = 0x%08x, "
			"Edi = 0x%08x, "
			"Esp = 0x%08x, "
			"Ebp = 0x%08x, "
			"Eip = 0x%08x], Teb: 0x%08x ["
			"StackBase = 0x%08x, "
			"StackLimit = 0x%08x, "
			"StackCommit = 0x%08x, "
			"StackCommitMax = 0x%08x, "
			"StackReserved = 0x%08x], CreateSuspended: 0x%08x) => 0x%08x; \n";

		Process process(ProcessHandle);
		process.ReadProcessImagePath();

		LogTraceTime(
			Time,
			mask,
			Sys->m_Id,
			*ThreadHandle,
			GetThreadId(*ThreadHandle),
			process.GetProcessHandle(),
			process.GetProcessId(),
			process.GetProcessImagePath(),
			DesiredAccess,
			ConstMaskToString(DesiredAccess, thread::AccessMasks).c_str(),
			ThreadContext,
			ThreadContext->Eax,
			ThreadContext->Ebx,
			ThreadContext->Ecx,
			ThreadContext->Edx,
			ThreadContext->Esi,
			ThreadContext->Edi,
			ThreadContext->Esp,
			ThreadContext->Ebp,
			ThreadContext->Eip,
			InitialTeb,
			InitialTeb->StackBase,
			InitialTeb->StackLimit,
			InitialTeb->StackCommit,
			InitialTeb->StackCommitMax,
			InitialTeb->StackReserved,
			CreateSuspended,
			Regs->EAX);

		return result;
	}
}

AllowLog thread::events::NtCreateThreadEx(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted)
{
	typedef NTSTATUS
	(NTAPI* fNtCreateThreadEx)(
		HANDLE* ThreadHandle,
		ACCESS_MASK DesiredAccess,
		OBJECT_ATTRIBUTES* ObjectAttributes,
		HANDLE ProcessHandle,
		VOID* lpStartAddress,
		VOID* lpParameter,
		ULONG Flags,
		SIZE_T StackZeroBits,
		SIZE_T SizeOfStackCommit,
		SIZE_T SizeOfStackReserve,
		VOID* lpBytesBuffer);

	AllowLog result = AllowLog::ALLOW_BOTH;

	if (!IsExecuted)
	{
		return result;
	}
	else
	{
		HANDLE* ThreadHandle = reinterpret_cast<HANDLE*>(Args[0]);
		ACCESS_MASK DesiredAccess = static_cast<ACCESS_MASK>(Args[1]);
		OBJECT_ATTRIBUTES* ObjectAttributes = reinterpret_cast<OBJECT_ATTRIBUTES*>(Args[2]);
		HANDLE ProcessHandle = reinterpret_cast<HANDLE>(Args[3]);
		VOID* lpStartAddress = reinterpret_cast<VOID*>(Args[4]);
		VOID* lpParameter = reinterpret_cast<CONTEXT*>(Args[5]);
		ULONG Flags = static_cast<ULONG>(Args[6]);
		SIZE_T StackZeroBits = static_cast<SIZE_T>(Args[7]);
		SIZE_T SizeOfStackCommit = static_cast<SIZE_T>(Args[8]);
		SIZE_T SizeOfStackReserve = static_cast<SIZE_T>(Args[9]);
		VOID* lpBytesBuffer = reinterpret_cast<VOID*>(Args[10]);

		if (NT_ERROR(Regs->EAX) || !ThreadHandle)
		{
			return result;
		}

		const char* mask = "~$CreateThreadEx <0x%x> (Handle: 0x%08x [Tid: 0x%04x], Handle: 0x%08x [Pid: 0x%04x, Image: \"%s\"], StartAddress: 0x%08x, Parameter: 0x%08x, Access: 0x%08x ['%s']) => 0x%08x;\n";

		Process process(ProcessHandle);
		process.ReadProcessImagePath();

		LogTraceTime(
			Time,
			mask,
			Sys->m_Id,
			*ThreadHandle,
			GetThreadId(*ThreadHandle),
			process.GetProcessHandle(),
			process.GetProcessId(),
			process.GetProcessImagePath(),
			lpStartAddress,
			lpParameter,
			DesiredAccess,
			ConstMaskToString(DesiredAccess, thread::AccessMasks).c_str(),
			Regs->EAX);

		return result;
	}
}