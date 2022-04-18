#include "regkey.h"
#include "tools.h"
#include "logger.h"
#include "analyzer.h"

using namespace logger;
using namespace tools;
using namespace analyzer;

AllowLog regkey::events::NtCreateKey(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted)
{
	typedef NTSTATUS
	(NTAPI* fNtCreateKey)(
		HANDLE* KeyHandle,
		ACCESS_MASK DesiredAccess,
		OBJECT_ATTRIBUTES* ObjectAttributes,
		ULONG TitleIndex,
		UNICODE_STRING* Class,
		ULONG CreateOptions,
		ULONG* Disposition);

	AllowLog result = AllowLog::ALLOW_BOTH;

	if (!IsExecuted)
	{
		return result;
	}
	else
	{
		HANDLE* KeyHandle = reinterpret_cast<HANDLE*>(Args[0]);
		ACCESS_MASK DesiredAccess = static_cast<ACCESS_MASK>(Args[1]);
		OBJECT_ATTRIBUTES* ObjectAttributes = reinterpret_cast<OBJECT_ATTRIBUTES*>(Args[2]);
		ULONG TitleIndex = static_cast<ULONG>(Args[3]);
		UNICODE_STRING* Class = reinterpret_cast<UNICODE_STRING*>(Args[4]);
		ULONG CreateOptions = static_cast<ULONG>(Args[5]);
		ULONG* Disposition = reinterpret_cast<ULONG*>(Args[6]);

		if (NT_ERROR(Regs->EAX) || !KeyHandle || !ObjectAttributes || !Disposition)
		{
			return result;
		}

		std::string classKey;
		OBJECT_HANDLE_INFORMATION ohi;

		UnicodeToAscii(Class->Buffer, classKey);

		if (!IsValueHandle(*KeyHandle, ohi))
		{
			return result;
		}

		const char* mask = "~$CreateKey <0x%x> (Handle: 0x%08x [%s: \"%s\"], Class: 0x%08x ['%s'], CreateOptions: 0x%08x ['%s'], Disposition: 0x%08x ['%s']) => 0x%08x;\n";

		LogTraceTime(
			Time,
			mask,
			Sys->m_Id,
			*KeyHandle,
			ohi.m_StrType.c_str(),
			ohi.m_StrName.c_str(),
			Class,
			classKey.c_str(),
			CreateOptions,
			ConstMaskToString(CreateOptions, regkey::CreateMasks).c_str(),
			*Disposition,
			ConstToString(*Disposition, regkey::DispositionConst).c_str(),
			Regs->EAX);

		return result;
	}
}

AllowLog regkey::events::NtDeleteKey(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted)
{
	typedef NTSTATUS
	(NTAPI* fNtDeleteKey)(
		HANDLE KeyHandle);

	AllowLog result = AllowLog::ALLOW_BOTH;

	if (!IsExecuted)
	{
		return result;
	}
	else
	{
		HANDLE KeyHandle = reinterpret_cast<HANDLE>(Args[0]);

		if (NT_ERROR(Regs->EAX))
		{
			return result;
		}
		
		OBJECT_HANDLE_INFORMATION ohi;

		if (!IsValueHandle(KeyHandle, ohi))
		{
			return result;
		}

		const char* mask = "~$DeleteKey <0x%x> (Handle: 0x%08x [%s: \"%s\"]) => 0x%08x;\n";

		LogTraceTime(
			Time,
			mask,
			Sys->m_Id,
			KeyHandle,
			ohi.m_StrType.c_str(),
			ohi.m_StrName.c_str(),
			Regs->EAX);

		return result;
	}
}

AllowLog regkey::events::NtDeleteValueKey(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted)
{
	typedef NTSTATUS
	(NTAPI* fNtDeleteValueKey)(
		HANDLE KeyHandle,
		UNICODE_STRING* ValueName);

	AllowLog result = AllowLog::ALLOW_BOTH;

	if (!IsExecuted)
	{
		HANDLE KeyHandle = reinterpret_cast<HANDLE>(Args[0]);
		UNICODE_STRING* ValueName = reinterpret_cast<UNICODE_STRING*>(Args[1]);

		OBJECT_HANDLE_INFORMATION ohi;

		IsValueHandle(KeyHandle, ohi);

		std::string valueKey;

		if (ValueName)
		{
			UnicodeToAscii(ValueName->Buffer, valueKey);
		}

		const char* mask = "$DeleteValueKey <0x%x> (Handle: 0x%08x [%s: \"%s\"], ValueName: 0x%08x [\"%s\"]);\n";

		LogTraceTime(
			Time,
			mask,
			Sys->m_Id,
			KeyHandle,
			ohi.m_StrType.c_str(),
			ohi.m_StrName.c_str(),
			ValueName,
			valueKey.c_str());

		return result;
	}
	else
	{
		HANDLE KeyHandle = reinterpret_cast<HANDLE>(Args[0]);
		UNICODE_STRING* ValueName = reinterpret_cast<UNICODE_STRING*>(Args[1]);

		if (NT_ERROR(Regs->EAX) || !ValueName)
		{
			return result;
		}

		OBJECT_HANDLE_INFORMATION ohi;
		std::string valueKey;

		UnicodeToAscii(ValueName->Buffer, valueKey);

		if (!IsValueHandle(KeyHandle, ohi))
		{
			return result;
		}

		const char* mask = "~$DeleteValueKey <0x%x> (Handle: 0x%08x [%s: \"%s\"], ValueName: 0x%08x ['%s']) => 0x%08x;\n";

		LogTraceTime(
			Time,
			mask,
			Sys->m_Id,
			KeyHandle,
			ohi.m_StrType.c_str(),
			ohi.m_StrName.c_str(),
			ValueName,
			valueKey.c_str(),
			Regs->EAX);

		return result;
	}
}

AllowLog regkey::events::NtOpenKey(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted)
{
	typedef NTSTATUS
	(NTAPI* fNtOpenKey)(
		HANDLE* KeyHandle,
		ACCESS_MASK DesiredAccess,
		OBJECT_ATTRIBUTES* ObjectAttributes);

	AllowLog result = AllowLog::ALLOW_BOTH;

	if (!IsExecuted)
	{
		return result;
	}
	else
	{
		HANDLE* KeyHandle = reinterpret_cast<HANDLE*>(Args[0]);
		ACCESS_MASK DesiredAccess = static_cast<ACCESS_MASK>(Args[1]);
		OBJECT_ATTRIBUTES* ObjectAttributes = reinterpret_cast<OBJECT_ATTRIBUTES*>(Args[2]);

		if (NT_ERROR(Regs->EAX) || !KeyHandle)
		{
			return result;
		}

		OBJECT_HANDLE_INFORMATION ohi;

		if (!IsValueHandle(*KeyHandle, ohi))
		{
			return result;
		}

		const char* mask = "~$OpenKey <0x%x> (Handle: 0x%08x [%s: \"%s\"], Access: 0x%08x ['%s']) => 0x%08x;\n";

		LogTraceTime(
			Time,
			mask,
			Sys->m_Id,
			*KeyHandle,
			ohi.m_StrType.c_str(),
			ohi.m_StrName.c_str(),
			DesiredAccess,
			ConstMaskToString(DesiredAccess, regkey::AccessMasks).c_str(),
			Regs->EAX);

		return result;
	}
}

AllowLog regkey::events::NtQueryKey(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted)
{
	typedef NTSTATUS
	(NTAPI* fNtQueryKey)(
		HANDLE KeyHandle,
		regkey::KEY_INFORMATION_CLASS KeyInformationClass,
		VOID* KeyInformation,
		ULONG Length,
		ULONG* ResultLength);

	AllowLog result = AllowLog::ALLOW_BOTH;

	if (!IsExecuted)
	{
		return result;
	}
	else
	{
		HANDLE KeyHandle = reinterpret_cast<HANDLE>(Args[0]);
		regkey::KEY_INFORMATION_CLASS KeyInformationClass = static_cast<regkey::KEY_INFORMATION_CLASS>(Args[1]);
		VOID* KeyInformation = reinterpret_cast<VOID*>(Args[2]);
		ULONG Length = static_cast<ULONG>(Args[3]);
		ULONG* ResultLength = reinterpret_cast<ULONG*>(Args[4]);

		if (NT_ERROR(Regs->EAX))
		{
			return result;
		}

		OBJECT_HANDLE_INFORMATION ohi;

		if (!IsValueHandle(KeyHandle, ohi))
		{
			return result;
		}

		const char* mask = "~$QueryKey <0x%x> (Handle: 0x%08x [%s: \"%s\"], KeyInfoClass: 0x%08x ['%s'], Buffer: 0x%08x [%s], Size: 0x%08x) => 0x%08x;\n";

		LogTraceTime(
			Time,
			mask,
			Sys->m_Id,
			KeyHandle,
			ohi.m_StrType.c_str(),
			ohi.m_StrName.c_str(),
			KeyInformationClass,
			ConstToString(KeyInformationClass, regkey::KeyInformationClass).c_str(),
			KeyInformation,
			HexBuffer(KeyInformation, Length).c_str(),
			Length,
			Regs->EAX);

		return result;
	}
}

AllowLog regkey::events::NtQueryValueKey(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted)
{
	typedef NTSTATUS
	(NTAPI* fNtQueryValueKey)(
		HANDLE KeyHandle,
		UNICODE_STRING* ValueName,
		regkey::KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
		VOID* KeyValueInformation,
		ULONG Length,
		ULONG* ResultLength);

	AllowLog result = AllowLog::ALLOW_BOTH;

	if (!IsExecuted)
	{
		return result;
	}
	else
	{
		HANDLE KeyHandle = reinterpret_cast<HANDLE>(Args[0]);
		UNICODE_STRING* ValueName = reinterpret_cast<UNICODE_STRING*>(Args[1]);
		regkey::KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass = static_cast<regkey::KEY_VALUE_INFORMATION_CLASS>(Args[2]);
		VOID* KeyValueInformation = reinterpret_cast<VOID*>(Args[3]);
		ULONG Length = static_cast<ULONG>(Args[4]);
		ULONG* ResultLength = reinterpret_cast<ULONG*>(Args[5]);

		if (NT_ERROR(Regs->EAX) || !ValueName || !KeyValueInformation)
		{
			return result;
		}

		OBJECT_HANDLE_INFORMATION ohi;
		
		std::string valueName;

		if (!IsValueHandle(KeyHandle, ohi) || 
			!UnicodeToAscii(ValueName->Buffer, valueName))
		{
			return result;
		}

		const char* mask = "~$QueryValueKey <0x%x> (Handle: 0x%08x [%s: \"%s\"], ValueName: 0x%08x [\"%s\"], KeyValueInfoClass: 0x%08x ['%s'], Buffer: 0x%08x [%s], Size: 0x%08x) = > 0x%08x; \n";

		LogTraceTime(
			Time,
			mask,
			Sys->m_Id,
			KeyHandle,
			ohi.m_StrType.c_str(),
			ohi.m_StrName.c_str(),
			ValueName,
			valueName.c_str(),
			KeyValueInformationClass,
			ConstToString(KeyValueInformationClass, regkey::KeyValueInformationClass).c_str(),
			KeyValueInformation,
			HexBuffer(KeyValueInformation, Length).c_str(),
			Length,
			Regs->EAX);

		return result;
	}
}

AllowLog regkey::events::NtSetValueKey(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted)
{
	typedef NTSTATUS
	(NTAPI* fNtSetValueKey)(
		HANDLE KeyHandle,
		UNICODE_STRING* ValueName,
		ULONG TitleIndex,
		ULONG Type,
		VOID* Data,
		ULONG DataSize);

	AllowLog result = AllowLog::ALLOW_BOTH;

	if (!IsExecuted)
	{
		return result;
	}
	else
	{
		HANDLE KeyHandle = reinterpret_cast<HANDLE>(Args[0]);
		UNICODE_STRING* ValueName = reinterpret_cast<UNICODE_STRING*>(Args[1]);
		ULONG TitleIndex = static_cast<ULONG>(Args[2]);
		ULONG Type = static_cast<ULONG>(Args[3]);
		VOID* Data = reinterpret_cast<VOID*>(Args[4]);
		ULONG DataSize = static_cast<ULONG>(Args[5]);

		if (NT_ERROR(Regs->EAX) || !ValueName || !Data)
		{
			return result;
		}

		OBJECT_HANDLE_INFORMATION ohi;

		std::string valueName;

		if (!IsValueHandle(KeyHandle, ohi) ||
			!UnicodeToAscii(ValueName->Buffer, valueName))
		{
			return result;
		}

		const char* mask = "~$SetValueKey <0x%x> (Handle: 0x%08x [%s: \"%s\"], Type: 0x%08x ['%s'], ValueName: 0x%08x [\"%s\"], Buffer: 0x%08x [%s], Size: 0x%08x) = > 0x%08x; \n";

		LogTraceTime(
			Time,
			mask,
			Sys->m_Id,
			KeyHandle,
			ohi.m_StrType.c_str(),
			ohi.m_StrName.c_str(),
			Type,
			ConstToString(Type, regkey::KeyValueTypes).c_str(),
			ValueName,
			valueName.c_str(),
			Data,
			HexBuffer(Data, DataSize).c_str(),
			DataSize,
			Regs->EAX);

		return result;
	}
}
