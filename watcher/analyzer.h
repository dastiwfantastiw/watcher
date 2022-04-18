#pragma once
#include "config.h"
#include "memory.h"

using namespace cfg;

namespace analyzer
{
	struct OBJECT_HANDLE_INFORMATION
	{
		Type        m_Types;
		std::string m_StrType;
		std::string m_StrName;

		OBJECT_HANDLE_INFORMATION() :
			m_Types(Type(NULL)),
			m_StrType(""),
			m_StrName("") {};
	};

	extern DWORD MinStrLength;
	extern DWORD MaxStrLength;
	extern BYTE  MaxPtr;

	bool IsValueArrayChar(char* Value, SIZE_T AvailableSize, SIZE_T& Length);
	bool IsValueArrayWideChar(wchar_t* Value, SIZE_T AvailableSize, SIZE_T& Length);
	bool IsValueHandle(HANDLE Value, OBJECT_HANDLE_INFORMATION& HandleInfo);
	bool IsValueAnsiString(ANSI_STRING* Value, SIZE_T AvailableSize);
	bool IsValueUnicodeString(UNICODE_STRING* Value, SIZE_T AvailableSize);
}