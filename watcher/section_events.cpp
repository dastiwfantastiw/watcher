#include "section.h"
#include "tools.h"
#include "process.h"
#include "logger.h"
#include "analyzer.h"

using namespace tools;
using namespace process;
using namespace logger;
using namespace analyzer;

AllowLog section::events::NtCreateSection(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted)
{
	typedef NTSTATUS
	(NTAPI* fNtCreateSection)(
		HANDLE* SectionHandle,
		ULONG DesiredAccess,
		OBJECT_ATTRIBUTES* ObjectAttributes,
		LARGE_INTEGER* MaximumSize,
		ULONG PageAttributes,
		ULONG SectionAttributes,
		HANDLE FileHandle);

	AllowLog result = AllowLog::ALLOW_BOTH;

	if (!IsExecuted)
	{
		return result;
	}
	else
	{
		HANDLE* SectionHandle = reinterpret_cast<HANDLE*>(Args[0]);
		ULONG DesiredAccess = static_cast<ULONG>(Args[1]);
		OBJECT_ATTRIBUTES* ObjectAttributes = reinterpret_cast<OBJECT_ATTRIBUTES*>(Args[2]);
		LARGE_INTEGER* MaximumSize = reinterpret_cast<LARGE_INTEGER*>(Args[3]);
		ULONG PageAttributes = static_cast<ULONG>(Args[4]);
		ULONG SectionAttributes = static_cast<ULONG>(Args[5]);
		HANDLE FileHandle = reinterpret_cast<HANDLE>(Args[6]);

		if (NT_ERROR(Regs->EAX) || !SectionHandle)
		{
			return result;
		}

		OBJECT_HANDLE_INFORMATION ohiSection;
		OBJECT_HANDLE_INFORMATION ohiFile;

		if (!IsValueHandle(*SectionHandle, ohiSection) ||
			!IsValueHandle(FileHandle, ohiFile))
		{
			return result;
		}

		const char* mask = "~$CreateSection <0x%x> (Handle: 0x%08x [%s: \"%s\"], Handle: 0x%08x [%s: \"%s\"], Access: 0x%08x ['%s'], Protection: 0x%08x ['%s'], Attributes: 0x%08x ['%s']) => 0x%08x;\n";

		LogTraceTime(
			Time,
			mask,
			Sys->m_Id,
			*SectionHandle,
			ohiSection.m_StrType.c_str(),
			ohiSection.m_StrName.c_str(),
			FileHandle,
			ohiFile.m_StrType.c_str(),
			ohiFile.m_StrName.c_str(),
			DesiredAccess,
			ConstMaskToString(DesiredAccess, section::AccessMasks).c_str(),
			PageAttributes,
			ConstMaskToString(PageAttributes, memory::ProtectionMasks).c_str(),
			SectionAttributes,
			ConstMaskToString(SectionAttributes, section::AttributesMasks).c_str(),
			Regs->EAX);

		return result;
	}
}

AllowLog section::events::NtMapViewOfSection(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted)
{
	typedef enum _SECTION_INHERIT
	{
		ViewShare = 1,
		ViewUnmap = 2
	} SECTION_INHERIT, * PSECTION_INHERIT;

	typedef NTSTATUS
	(NTAPI* fNtMapViewOfSection)(
		HANDLE SectionHandle,
		HANDLE ProcessHandle,
		VOID** BaseAddress,
		ULONG ZeroBits,
		ULONG CommitSize,
		LARGE_INTEGER* SectionOffset,
		ULONG* ViewSize,
		SECTION_INHERIT InheritDisposition,
		ULONG AllocationType,
		ULONG Protect);

	AllowLog result = AllowLog::ALLOW_BOTH;

	if (!IsExecuted)
	{
		return result;
	}
	else
	{
		HANDLE SectionHandle = reinterpret_cast<HANDLE>(Args[0]);
		HANDLE ProcessHandle = reinterpret_cast<HANDLE>(Args[1]);
		VOID** BaseAddress = reinterpret_cast<VOID**>(Args[2]);
		ULONG* ViewSize = reinterpret_cast<ULONG*>(Args[6]);
		ULONG AllocationType = static_cast<ULONG>(Args[8]);
		ULONG Protect = static_cast<ULONG>(Args[9]);

		if (NT_ERROR(Regs->EAX) || !BaseAddress || !ViewSize)
		{
			return result;
		}

		OBJECT_HANDLE_INFORMATION ohi;

		if (!IsValueHandle(SectionHandle, ohi))
		{
			return result;
		}

		const char* mask = "~$MapViewOfSection <0x%x> (Handle: 0x%08x [%s: \"%s\"], Handle: 0x%08x [Pid: 0x%04x, Image: \"%s\"], BaseAddress: 0x%08x, Size: 0x%08x, Allocation: 0x%08x ['%s'], Protection: 0x%08x ['%s']) => 0x%08x;\n";

		Process process(ProcessHandle);
		process.ReadProcessImagePath();

		LogTraceTime(
			Time,
			mask,
			Sys->m_Id,
			SectionHandle,
			ohi.m_StrType.c_str(),
			ohi.m_StrName.c_str(),
			process.GetProcessHandle(),
			process.GetProcessId(),
			process.GetProcessImagePath(),
			*BaseAddress,
			*ViewSize,
			AllocationType,
			ConstMaskToString(AllocationType, memory::AllocationMasks).c_str(),
			Protect,
			ConstMaskToString(Protect, memory::ProtectionMasks).c_str(),
			Regs->EAX);

		return result;
	}
}

AllowLog section::events::NtOpenSection(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted)
{
	typedef NTSTATUS
	(NTAPI* fNtOpenSection)(
		HANDLE* SectionHandle,
		ACCESS_MASK DesiredAccess,
		OBJECT_ATTRIBUTES* ObjectAttributes);

	AllowLog result = AllowLog::ALLOW_BOTH;

	if (!IsExecuted)
	{
		return result;
	}
	else
	{
		HANDLE* SectionHandle = reinterpret_cast<HANDLE*>(Args[0]);
		ACCESS_MASK DesiredAccess = static_cast<ACCESS_MASK>(Args[1]);

		if (NT_ERROR(Regs->EAX) || !SectionHandle)
		{
			return result;
		}

		OBJECT_HANDLE_INFORMATION ohi;

		if (!IsValueHandle(*SectionHandle, ohi))
		{
			return result;
		}

		const char* mask = "~$OpenSection <0x%x> (Handle: 0x%08x [%s: \"%s\"], Access: 0x%08x ['%s']) => 0x%08x;\n";

		LogTraceTime(
			Time,
			mask,
			Sys->m_Id,
			SectionHandle,
			ohi.m_StrType.c_str(),
			ohi.m_StrName.c_str(),
			DesiredAccess,
			ConstMaskToString(DesiredAccess, section::AccessMasks).c_str(),
			Regs->EAX);

		return result;
	}
}

AllowLog section::events::NtExtendSection(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted)
{
	typedef NTSTATUS
	(NTAPI* fNtExtendSection)(
		HANDLE SectionHandle,
		LARGE_INTEGER* NewSectionSize);

	AllowLog result = AllowLog::ALLOW_BOTH;

	if (!IsExecuted)
	{
		return result;
	}
	else
	{
		HANDLE SectionHandle = reinterpret_cast<HANDLE>(Args[0]);
		LARGE_INTEGER* NewSectionSize = reinterpret_cast<LARGE_INTEGER*>(Args[1]);

		if (NT_ERROR(Regs->EAX) || !NewSectionSize)
		{
			return result;
		}

		OBJECT_HANDLE_INFORMATION ohi;

		if (!IsValueHandle(SectionHandle, ohi))
		{
			return result;
		}

		const char* mask = "~$ExtendSection <0x%x> (Handle: 0x%08x [%s: \"%s\"], Size: 0x%08x) => 0x%08x;\n";

		LogTraceTime(
			Time,
			mask,
			Sys->m_Id,
			SectionHandle,
			ohi.m_StrType.c_str(),
			ohi.m_StrName.c_str(),
			*NewSectionSize,
			Regs->EAX);

		return result;
	}
}

AllowLog section::events::NtUnmapViewOfSection(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted)
{
	typedef NTSTATUS
	(NTAPI* fNtUnmapViewOfSection)(
		HANDLE ProcessHandle,
		VOID* BaseAddress);

	AllowLog result = AllowLog::ALLOW_BOTH;

	if (!IsExecuted)
	{
		return result;
	}
	else
	{
		HANDLE ProcessHandle = reinterpret_cast<HANDLE>(Args[0]);
		VOID* BaseAddress = reinterpret_cast<VOID*>(Args[1]);

		if (NT_ERROR(Regs->EAX))
		{
			return result;
		}

		const char* mask = "~$UnmapViewOfSection <0x%x> (Handle: 0x%08x [Pid: 0x%04x, Image: \"%s\"], BaseAddress: 0x%08x) => 0x%08x;\n";

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
			Regs->EAX);

		return result;
	}
}