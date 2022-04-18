#pragma once
#include "config.h"
#include <map>

using namespace cfg;

namespace regkey
{
	typedef enum _KEY_INFORMATION_CLASS 
	{
		KeyBasicInformation,
		KeyNodeInformation,
		KeyFullInformation,
		KeyNameInformation,
		KeyCachedInformation,
		KeyFlagsInformation,
		KeyVirtualizationInformation,
		KeyHandleTagsInformation,
		KeyTrustInformation,
		KeyLayerInformation,
		MaxKeyInfoClass
	} KEY_INFORMATION_CLASS;

	typedef enum _KEY_VALUE_INFORMATION_CLASS 
	{
		KeyValueBasicInformation,
		KeyValueFullInformation,
		KeyValuePartialInformation,
		KeyValueFullInformationAlign64,
		KeyValuePartialInformationAlign64,
		KeyValueLayerInformation,
		MaxKeyValueInfoClass
	} KEY_VALUE_INFORMATION_CLASS;

	extern std::map<ACCESS_MASK, const char*> AccessMasks;
	extern std::map<ACCESS_MASK, const char*> CreateMasks;
	extern std::map<DWORD, const char*> DispositionConst;
	extern std::map<DWORD, const char*> KeyInformationClass;
	extern std::map<DWORD, const char*> KeyValueInformationClass;
	extern std::map<DWORD, const char*> KeyValueTypes;

	namespace events
	{
		AllowLog NtCreateKey(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted);
		AllowLog NtDeleteKey(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted);
		AllowLog NtDeleteValueKey(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted);
		AllowLog NtOpenKey(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted);
		AllowLog NtQueryKey(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted);
		AllowLog NtQueryValueKey(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted);
		AllowLog NtSetValueKey(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted);
	}
}