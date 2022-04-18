#include "file.h"
#include "logger.h"
#include "tools.h"

using namespace logger;
using namespace tools;

AllowLog file::events::NtCreateFile(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted)
{
	typedef NTSTATUS
	(NTAPI* fNtCreateFile)(
		HANDLE* FileHandle,
		ACCESS_MASK DesiredAccess,
		OBJECT_ATTRIBUTES* ObjectAttributes,
		IO_STATUS_BLOCK* IoStatusBlock,
		LARGE_INTEGER* AllocationSize,
		ULONG FileAttributes,
		ULONG ShareAccess,
		ULONG CreateDisposition,
		ULONG CreateOptions,
		VOID* EaBuffer,
		ULONG EaLength);

	AllowLog result = AllowLog::ALLOW_BOTH;

	if (!IsExecuted)
	{
		return result;
	}
	else
	{
		HANDLE* FileHandle = reinterpret_cast<HANDLE*>(Args[0]);
		ACCESS_MASK DesiredAccess = static_cast<ACCESS_MASK>(Args[1]);
		OBJECT_ATTRIBUTES* ObjectAttributes = reinterpret_cast<OBJECT_ATTRIBUTES*>(Args[2]);
		IO_STATUS_BLOCK* IoStatusBlock = reinterpret_cast<IO_STATUS_BLOCK*>(Args[3]);
		LARGE_INTEGER* AllocationSize = reinterpret_cast<LARGE_INTEGER*>(Args[4]);
		ULONG FileAttributes = static_cast<ULONG>(Args[5]);
		ULONG ShareAccess = static_cast<ULONG>(Args[6]);
		ULONG CreateDisposition = static_cast<ULONG>(Args[7]);
		ULONG CreateOptions = static_cast<ULONG>(Args[8]);
		VOID* EaBuffer = reinterpret_cast<VOID*>(Args[9]);
		ULONG EaLength = static_cast<ULONG>(Args[10]);

		if (NT_ERROR(Regs->EAX))
		{
			return result;
		}

		OBJECT_HANDLE_INFORMATION ohi;
		if (!IsValueHandle(*FileHandle, ohi))
		{
			return result;
		}

		const char* mask = "~$CreateFile <0x%x> (Handle: 0x%08x [%s: \"%s\"], Access: 0x%08x ['%s'], Attribute: 0x%08x ['%s'], ShareAccess: 0x%08x ['%s']) => 0x%08x;\n";

		LogTraceTime(
			Time,
			mask,
			Sys->m_Id,
			*FileHandle,
			ohi.m_StrType.c_str(),
			ohi.m_StrName.c_str(),
			DesiredAccess,
			ConstMaskToString(DesiredAccess, file::AccessMasks).c_str(),
			FileAttributes,
			ConstMaskToString(FileAttributes, file::AttributesMasks).c_str(),
			ShareAccess,
			ConstMaskToString(ShareAccess, file::ShareAccessMasks).c_str(),
			Regs->EAX);

		return result;
	}
}

AllowLog file::events::NtReadFile(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted)
{
	typedef VOID(NTAPI* IO_APC_ROUTINE)(
		VOID* ApcContext,
		IO_STATUS_BLOCK* IoStatusBlock,
		ULONG Reserved);

	typedef NTSTATUS
	(NTAPI* fNtReadFile)(
		HANDLE FileHandle,
		HANDLE Event,
		IO_APC_ROUTINE* ApcRoutine,
		VOID* ApcContext,
		IO_STATUS_BLOCK* IoStatusBlock,
		VOID* Buffer,
		ULONG Length,
		LARGE_INTEGER* ByteOffset,
		ULONG* Key);

	AllowLog result = AllowLog::ALLOW_BOTH;

	if (!IsExecuted)
	{
		return result;
	}
	else
	{
		HANDLE FileHandle = reinterpret_cast<HANDLE>(Args[0]);
		HANDLE Event = reinterpret_cast<HANDLE>(Args[1]);
		IO_APC_ROUTINE* ApcRoutine = reinterpret_cast<IO_APC_ROUTINE*>(Args[2]);
		VOID* ApcContext = reinterpret_cast<VOID*>(Args[3]);
		IO_STATUS_BLOCK* IoStatusBlock = reinterpret_cast<IO_STATUS_BLOCK*>(Args[4]);
		VOID* Buffer = reinterpret_cast<VOID*>(Args[5]);
		ULONG Length = static_cast<ULONG>(Args[6]);
		LARGE_INTEGER* ByteOffset = reinterpret_cast<LARGE_INTEGER*>(Args[7]);
		ULONG* Key = reinterpret_cast<ULONG*>(Args[8]);

		if (NT_ERROR(Regs->EAX))
		{
			return result;
		}

		OBJECT_HANDLE_INFORMATION ohi;

		if (!IsValueHandle(FileHandle, ohi))
		{
			return result;
		}

		const char* mask = "~$ReadFile <0x%x> (Handle: 0x%08x [%s: \"%s\"], Event: 0x%08x, Buffer: 0x%08x [%s], Size: 0x%08x, Offset: 0x%08x) => 0x%08x;\n";

		LogTraceTime(
			Time,
			mask,
			Sys->m_Id,
			FileHandle,
			ohi.m_StrType.c_str(),
			ohi.m_StrName.c_str(),
			Event,
			Buffer,
			HexBuffer(Buffer, Length).c_str(),
			Length,
			ByteOffset,
			Regs->EAX);

		return result;
	}
}

AllowLog file::events::NtWriteFile(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted)
{
	typedef VOID(NTAPI* IO_APC_ROUTINE)(
		VOID* ApcContext,
		IO_STATUS_BLOCK* IoStatusBlock,
		ULONG Reserved);

	typedef NTSTATUS
	(NTAPI* fNtWriteFile)(
		HANDLE FileHandle,
		HANDLE Event,
		IO_APC_ROUTINE* ApcRoutine,
		VOID* ApcContext,
		IO_STATUS_BLOCK* IoStatusBlock,
		VOID* Buffer,
		ULONG Length,
		LARGE_INTEGER* ByteOffset,
		ULONG* Key);

	AllowLog result = AllowLog::ALLOW_BOTH;

	if (!IsExecuted)
	{
		return result;
	}
	else
	{
		HANDLE FileHandle = reinterpret_cast<HANDLE>(Args[0]);
		HANDLE Event = reinterpret_cast<HANDLE>(Args[1]);
		IO_APC_ROUTINE* ApcRoutine = reinterpret_cast<IO_APC_ROUTINE*>(Args[2]);
		VOID* ApcContext = reinterpret_cast<VOID*>(Args[3]);
		IO_STATUS_BLOCK* IoStatusBlock = reinterpret_cast<IO_STATUS_BLOCK*>(Args[4]);
		VOID* Buffer = reinterpret_cast<VOID*>(Args[5]);
		ULONG Length = static_cast<ULONG>(Args[6]);
		LARGE_INTEGER* ByteOffset = reinterpret_cast<LARGE_INTEGER*>(Args[7]);
		ULONG* Key = reinterpret_cast<ULONG*>(Args[8]);

		if (NT_ERROR(Regs->EAX))
		{
			return result;
		}

		OBJECT_HANDLE_INFORMATION ohi;

		if (!IsValueHandle(FileHandle, ohi))
		{
			return result;
		}

		const char* mask = "~$WriteFile <0x%x> (Handle: 0x%08x [%s: \"%s\"], Event: 0x%08x, Buffer: 0x%08x [%s], Size: 0x%08x, Offset: 0x%08x) => 0x%08x;\n";

		LogTraceTime(
			Time,
			mask,
			Sys->m_Id,
			FileHandle,
			ohi.m_StrType.c_str(),
			ohi.m_StrName.c_str(),
			Event,
			Buffer,
			HexBuffer(Buffer, Length).c_str(),
			Length,
			ByteOffset,
			Regs->EAX);

		return result;
	}
}

AllowLog file::events::NtDeleteFile(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted)
{
	typedef NTSTATUS
	(NTAPI* fNtDeleteFile)(
		OBJECT_ATTRIBUTES* ObjectAttributes);

	AllowLog result = AllowLog::ALLOW_BOTH;

	if (!IsExecuted)
	{
		return result;
	}
	else
	{
		OBJECT_ATTRIBUTES* ObjectAttributes = reinterpret_cast<OBJECT_ATTRIBUTES*>(Args[0]);

		if (NT_ERROR(Regs->EAX) || !ObjectAttributes || !ObjectAttributes->ObjectName)
		{
			return result;
		}

		std::string objectName;

		if (!UnicodeToAscii(ObjectAttributes->ObjectName->Buffer, objectName))
		{
			return result;
		}

		const char* mask = "~$DeleteFile <0x%x> (ObjectAttribute: 0x%08x ['%s']) => 0x%08x;\n";

		LogTraceTime(
			Time,
			mask,
			Sys->m_Id,
			ObjectAttributes,
			objectName.c_str(),
			Regs->EAX);

		return result;
	}
}

AllowLog file::events::NtDeviceIoControlFile(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted)
{
	typedef VOID(NTAPI* IO_APC_ROUTINE)(
		VOID* ApcContext,
		IO_STATUS_BLOCK* IoStatusBlock,
		ULONG Reserved);

	typedef NTSTATUS
	(NTAPI* fNtDeviceIoControlFile)(
		HANDLE FileHandle,
		HANDLE Event,
		IO_APC_ROUTINE* ApcRoutine,
		VOID* ApcContext,
		IO_STATUS_BLOCK* IoStatusBlock,
		ULONG IoControlCode,
		VOID* InputBuffer,
		ULONG InputBufferLength,
		VOID* OutputBuffer,
		ULONG OutputBufferLength);

	AllowLog result = AllowLog::ALLOW_BOTH;

	if (!IsExecuted)
	{
		return result;
	}
	else
	{
		HANDLE FileHandle = reinterpret_cast<HANDLE>(Args[0]);
		HANDLE Event = reinterpret_cast<HANDLE>(Args[1]);
		IO_APC_ROUTINE* ApcRoutine = reinterpret_cast<IO_APC_ROUTINE*>(Args[2]);
		VOID* ApcContext = reinterpret_cast<VOID*>(Args[3]);
		IO_STATUS_BLOCK* IoStatusBlock = reinterpret_cast<IO_STATUS_BLOCK*>(Args[4]);
		ULONG IoControlCode = static_cast<ULONG>(Args[5]);
		VOID* InputBuffer = reinterpret_cast<VOID*>(Args[6]);
		ULONG InputBufferLength = static_cast<ULONG>(Args[7]);
		VOID* OutputBuffer = reinterpret_cast<VOID*>(Args[8]);
		ULONG OutputBufferLength = static_cast<ULONG>(Args[9]);

		if (NT_ERROR(Regs->EAX))
		{
			return result;
		}

		OBJECT_HANDLE_INFORMATION ohiFile;
		OBJECT_HANDLE_INFORMATION ohiEvent;

		if (!IsValueHandle(FileHandle, ohiFile))
		{
			return result;
		}

		IsValueHandle(Event, ohiEvent);

		const char* mask = "~$DeviceIoControlFile <0x%x> (Handle: 0x%08x [%s: \"%s\"], Handle: 0x%08x [%s: \"%s\"], InpBuffer: 0x%08x [%s], Size: 0x%08x, OutBuffer: 0x%08x [%s], Size: 0x%08x) => 0x%08x;\n";

		LogTraceTime(
			Time,
			mask,
			Sys->m_Id,
			FileHandle,
			ohiFile.m_StrType.c_str(),
			ohiFile.m_StrName.c_str(),
			Event,
			ohiEvent.m_StrType.c_str(),
			ohiEvent.m_StrName.c_str(),
			InputBuffer,
			HexBuffer(InputBuffer, InputBufferLength).c_str(),
			InputBufferLength,
			OutputBuffer,
			HexBuffer(OutputBuffer, OutputBufferLength).c_str(),
			OutputBufferLength,
			Regs->EAX);

		return result;
	}
}

AllowLog file::events::NtOpenFile(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted)
{
	typedef NTSTATUS
	(NTAPI* fNtOpenFile)(
		HANDLE* FileHandle,
		ACCESS_MASK DesiredAccess,
		OBJECT_ATTRIBUTES* ObjectAttributes,
		IO_STATUS_BLOCK* IoStatusBlock,
		ULONG ShareAccess,
		ULONG OpenOptions);

	AllowLog result = AllowLog::ALLOW_BOTH;

	if (!IsExecuted)
	{
		return result;
	}
	else
	{
		HANDLE* FileHandle = reinterpret_cast<HANDLE*>(Args[0]);
		ACCESS_MASK DesiredAccess = static_cast<ACCESS_MASK>(Args[1]);
		OBJECT_ATTRIBUTES* ObjectAttributes = reinterpret_cast<OBJECT_ATTRIBUTES*>(Args[2]);
		IO_STATUS_BLOCK* IoStatusBlock = reinterpret_cast<IO_STATUS_BLOCK*>(Args[3]);
		ULONG ShareAccess = static_cast<ULONG>(Args[4]);
		ULONG OpenOptions = static_cast<ULONG>(Args[5]);

		if (NT_ERROR(Regs->EAX) || !FileHandle)
		{
			return result;
		}

		OBJECT_HANDLE_INFORMATION ohi;

		if (!IsValueHandle(*FileHandle, ohi))
		{
			return result;
		}

		const char* mask = "~$OpenFile <0x%x> (Handle: 0x%08x [%s: \"%s\"], Access: 0x%08x ['%s'], ShareAccess: 0x%08x ['%s'], OpenOptions: 0x%08x ['%s']) => 0x%08x;\n";

		LogTraceTime(
			Time,
			mask,
			Sys->m_Id,
			*FileHandle,
			ohi.m_StrType.c_str(),
			ohi.m_StrName.c_str(),
			DesiredAccess,
			ConstMaskToString(DesiredAccess, file::AccessMasks).c_str(),
			ShareAccess,
			ConstMaskToString(ShareAccess, file::ShareAccessMasks).c_str(),
			OpenOptions,
			ConstMaskToString(OpenOptions, file::OpenMasks).c_str(),
			Regs->EAX);

		return result;
	}
}
