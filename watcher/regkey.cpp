#include "regkey.h"
#include <map>

namespace regkey
{
	std::map<ACCESS_MASK, const char*> AccessMasks =
	{
		{0x0001, "KEY_QUERY_VALUE"},
		{0x0002, "KEY_SET_VALUE"},
		{0x0004, "KEY_CREATE_SUB_KEY"},
		{0x0008, "KEY_ENUMERATE_SUB_KEYS"},
		{0x0010, "KEY_NOTIFY"},
		{0x0020, "KEY_CREATE_LINK"},
		{0x0200, "KEY_WOW64_32KEY"},
		{0x0100, "KEY_WOW64_64KEY"},
		{0x0300, "KEY_WOW64_RES"}
	};

	std::map<ACCESS_MASK, const char*> CreateMasks =
	{
		{0x00000000, "REG_OPTION_RESERVED"},
		{0x00000000, "REG_OPTION_NON_VOLATILE"},
		{0x00000001, "REG_OPTION_VOLATILE"},
		{0x00000002, "REG_OPTION_CREATE_LINK"},
		{0x00000004, "REG_OPTION_BACKUP_RESTORE"},
		{0x00000008, "REG_OPTION_OPEN_LINK"},
		{0x00000010, "REG_OPTION_DONT_VIRTUALIZE"}
	};

	std::map<DWORD, const char*> DispositionConst =
	{
		{0x00000001, "REG_CREATED_NEW_KEY"},
		{0x00000002, "REG_OPENED_EXISTING_KEY"}
	};

	std::map<DWORD, const char*> KeyInformationClass =
	{
		{0, "KeyBasicInformation"},
		{1, "KeyNodeInformation"},
		{2, "KeyFullInformation"},
		{3, "KeyNameInformation"},
		{4, "KeyCachedInformation"},
		{5, "KeyFlagsInformation"},
		{6, "KeyVirtualizationInformation"},
		{7, "KeyHandleTagsInformation"},
		{8, "KeyTrustInformation"},
		{9, "KeyLayerInformation"},
		{10, "MaxKeyInfoClass"}
	};

	std::map<DWORD, const char*> KeyValueInformationClass =
	{
		{0, "KeyValueBasicInformation"},
		{1, "KeyValueFullInformation"},
		{2, "KeyValuePartialInformation"},
		{3, "KeyValueFullInformationAlign64"},
		{4, "KeyValuePartialInformationAlign64"},
		{5, "KeyValueLayerInformation"},
		{6, "MaxKeyValueInfoClass"}
	};

	std::map<DWORD, const char*> KeyValueTypes =
	{
		 {0	, "REG_NONE"},
		 {1	, "REG_SZ"},
		 {2	, "REG_EXPAND_SZ"},
		 {3	, "REG_BINARY"},
		 {4	, "REG_DWORD"},
		 {4	, "REG_DWORD_LITTLE_ENDIAN"},
		 {5	, "REG_DWORD_BIG_ENDIAN"},
		 {6	, "REG_LINK"},
		 {7	, "REG_MULTI_SZ"},
		 {8	, "REG_RESOURCE_LIST"},
		 {9	, "REG_FULL_RESOURCE_DESCRIPTOR"},
		 {10, "REG_RESOURCE_REQUIREMENTS_LIST"},
		 {11, "REG_QWORD"},
		 {11, "REG_QWORD_LITTLE_ENDIAN"}
	};
}