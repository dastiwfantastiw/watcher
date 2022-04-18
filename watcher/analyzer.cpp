#include "analyzer.h"
#include "config.h"
#include "memory.h"
#include "tools.h"

using namespace memory;
using namespace tools;

namespace analyzer
{
	DWORD MinStrLength = NULL;
	DWORD MaxStrLength = NULL;
	BYTE  MaxPtr = NULL;
}

bool analyzer::IsValueArrayChar(char* Value, SIZE_T AvailableSize, SIZE_T& Length)
{
	if (MinStrLength > AvailableSize)
	{
		return false;
	}

	for (SIZE_T length = 0; (length <= MaxStrLength) && (length < AvailableSize); length++)
	{
		if ((Value[length] == '\0') &&
			(MinStrLength <= length))
		{
			Length = length;
			return true;
		}

		if ((Value[length] == '\n') ||
			(Value[length] == '\t') ||
			(Value[length] == '\r'))
		{
			continue;
		}

		if ((Value[length] < 32) ||
			(Value[length] > 126))
		{
			return false;
		}
	}
	return false;
}

bool analyzer::IsValueArrayWideChar(wchar_t* Value, SIZE_T AvailableSize, SIZE_T& Length)
{
	if (MinStrLength > AvailableSize)
	{
		return false;
	}

	char* charValue = reinterpret_cast<char*>(Value);

	for (SIZE_T length = 0; (length <= MaxStrLength) && (length < AvailableSize) ; length++)
	{
		if (length % 2)
		{
			if (charValue[length])
			{
				return false;
			}
		}
		else
		{
			if ((charValue[length] == '\n') ||
				(charValue[length] == '\t') ||
				(charValue[length] == '\r'))
			{
				continue;
			}

			if ((charValue[length] == '\0') &&
				(MinStrLength <= length))
			{
				Length = length;
				return true;
			}

			if ((charValue[length] < 32) ||
				(charValue[length] > 126))
			{
				return false;
			}
		}
	}
	return false;
}

bool analyzer::IsValueHandle(HANDLE Value, OBJECT_HANDLE_INFORMATION& HandleInfo)
{
	UNICODE_STRING* buffer = NULL;
	DWORD size = 0;

	HandleInfo.m_Types = Type(NULL);

	NTSTATUS stType = QueryObject(Value, tools::ObjectTypeInformation, NULL, NULL, &size);
	if (!size ||
		stType == STATUS_INVALID_HANDLE ||
		stType == STATUS_INVALID_PARAMETER)
	{
		return false;
	}

	buffer = static_cast<UNICODE_STRING*>(Alloc(size + 1));
	if (!buffer)
	{
		return false;
	}

	if (NT_ERROR(QueryObject(Value, tools::ObjectTypeInformation, buffer, size + 1, NULL)))
	{
		Free(buffer);
		return false;
	}

	if (buffer->Length)
	{

		if (!UnicodeToAscii(buffer->Buffer, HandleInfo.m_StrType) ||
			HandleInfo.m_StrType.empty())
		{
			Free(buffer);
			return false;
		}

		if (!HandleInfo.m_StrType.compare(0, 4, "Proc"))
		{
			HandleInfo.m_Types = Type::PROCESS;
		}
		else if (!HandleInfo.m_StrType.compare(0, 4, "File"))
		{
			HandleInfo.m_Types = Type::FILE;
		}
		else if (!HandleInfo.m_StrType.compare(0, 4, "Thre"))
		{
			HandleInfo.m_Types = Type::THREAD;
		}
		else if (!HandleInfo.m_StrType.compare(0, 4, "Muta"))
		{
			HandleInfo.m_Types = Type::MUTANT;
		}
		else if (!HandleInfo.m_StrType.compare(0, 3, "Key"))
		{
			HandleInfo.m_Types = Type::REGKEY;
		}
		else if (!HandleInfo.m_StrType.compare(0, 3, "Sec"))
		{
			HandleInfo.m_Types = Type::SECTION;
		}

		NTSTATUS stName = QueryObject(Value, tools::ObjectNameInformation, NULL, NULL, &size);
		if (!size ||
			stName == STATUS_INVALID_HANDLE ||
			stName == STATUS_INVALID_PARAMETER)
		{
			return false;
		}

		buffer = static_cast<UNICODE_STRING*>(ReAlloc(buffer, size + 1));
		if (!buffer)
		{
			Free(buffer);
			return false;
		}

		if (NT_ERROR(QueryObject(Value, tools::ObjectNameInformation, buffer, size + 1, NULL)))
		{
			Free(buffer);
			return false;
		}

		if (buffer->Length)
		{
			if (!UnicodeToAscii(buffer->Buffer, HandleInfo.m_StrName) ||
				HandleInfo.m_StrName.empty())
			{
				Free(buffer);
				return false;
			}
		}
	}

	Free(buffer);
	return true;
}

bool analyzer::IsValueAnsiString(ANSI_STRING* Value, SIZE_T AvailableSize)
{
	SIZE_T aBufferSize = 0;
	SIZE_T length = 0;

	if (AvailableSize < sizeof(ANSI_STRING))
	{
		return false;
	}

	if (IsBadReadPointer(Value->Buffer, aBufferSize))
	{
		return false;
	}

	if (!IsValueArrayChar(Value->Buffer, aBufferSize, length) ||
		length != Value->Length)
	{
		return false;
	}

	return true;
}

bool analyzer::IsValueUnicodeString(UNICODE_STRING* Value, SIZE_T AvailableSize)
{
	SIZE_T uBufferSize = 0;
	SIZE_T length = 0;

	if (AvailableSize < sizeof(UNICODE_STRING))
	{
		return false;
	}

	if (IsBadReadPointer(Value->Buffer, uBufferSize))
	{
		return false;
	}

	if (!IsValueArrayWideChar(Value->Buffer, uBufferSize, length) ||
		length != Value->Length)
	{
		return false;
	}

	return true;
}