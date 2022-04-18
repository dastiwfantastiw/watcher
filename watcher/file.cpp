#include "file.h"

namespace file
{
	std::map<ACCESS_MASK, const char*> AccessMasks =
	{
		{STANDARD_RIGHTS_READ | FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA | SYNCHRONIZE, "FILE_GENERIC_READ"},
		{STANDARD_RIGHTS_WRITE | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | FILE_APPEND_DATA | SYNCHRONIZE, "FILE_GENERIC_WRITE"},
		{STANDARD_RIGHTS_EXECUTE | FILE_READ_ATTRIBUTES | FILE_EXECUTE | SYNCHRONIZE, "FILE_GENERIC_EXECUTE"}
	};

	std::map<ACCESS_MASK, const char*> ShareAccessMasks =
	{
		{0x00000001, "FILE_SHARE_READ"},
		{0x00000002, "FILE_SHARE_WRITE"},
		{0x00000004, "FILE_SHARE_DELETE"},
	};

	std::map<ACCESS_MASK, const char*> AttributesMasks =
	{
		{0x00000001, "FILE_ATTRIBUTE_READONLY"},
		{0x00000002, "FILE_ATTRIBUTE_HIDDEN"},
		{0x00000004, "FILE_ATTRIBUTE_SYSTEM"},
		{0x00000010, "FILE_ATTRIBUTE_DIRECTORY"},
		{0x00000020, "FILE_ATTRIBUTE_ARCHIVE"},
		{0x00000040, "FILE_ATTRIBUTE_DEVICE"},
		{0x00000080, "FILE_ATTRIBUTE_NORMAL"},
		{0x00000100, "FILE_ATTRIBUTE_TEMPORARY"},
		{0x00000200, "FILE_ATTRIBUTE_SPARSE_FILE"},
		{0x00000400, "FILE_ATTRIBUTE_REPARSE_POINT"},
		{0x00000800, "FILE_ATTRIBUTE_COMPRESSED"},
		{0x00001000, "FILE_ATTRIBUTE_OFFLINE"},
		{0x00002000, "FILE_ATTRIBUTE_NOT_CONTENT_INDEXED"},
		{0x00004000, "FILE_ATTRIBUTE_ENCRYPTED"},
		{0x00008000, "FILE_ATTRIBUTE_INTEGRITY_STREAM"},
		{0x00010000, "FILE_ATTRIBUTE_VIRTUAL"},
		{0x00020000, "FILE_ATTRIBUTE_NO_SCRUB_DATA"},
		{0x00040000, "FILE_ATTRIBUTE_EA"},
		{0x00080000, "FILE_ATTRIBUTE_PINNED"},
		{0x00100000, "FILE_ATTRIBUTE_UNPINNED"},
		{0x00040000, "FILE_ATTRIBUTE_RECALL_ON_OPEN"},
		{0x20000000, "FILE_ATTRIBUTE_STRICTLY_SEQUENTIAL"},
	};

	std::map<ACCESS_MASK, const char*> OpenMasks =
	{
		{0x00000001, "FILE_DIRECTORY_FILE"},
		{0x00000002, "FILE_WRITE_THROUGH"},
		{0x00000004, "FILE_SEQUENTIAL_ONLY"},
		{0x00000008, "FILE_NO_INTERMEDIATE_BUFFERING"},
		{0x00000010, "FILE_SYNCHRONOUS_IO_ALERT"},
		{0x00000020, "FILE_SYNCHRONOUS_IO_NONALERT"},
		{0x00000040, "FILE_NON_DIRECTORY_FILE"},
		{0x00000080, "FILE_CREATE_TREE_CONNECTION"},
		{0x00000100, "FILE_COMPLETE_IF_OPLOCKED"},
		{0x00000200, "FILE_NO_EA_KNOWLEDGE"},
		{0x00000400, "FILE_OPEN_REMOTE_INSTANCE"},
		{0x00000800, "FILE_RANDOM_ACCESS"},
		{0x00001000, "FILE_DELETE_ON_CLOSE"},
		{0x00002000, "FILE_OPEN_BY_FILE_ID"},
		{0x00004000, "FILE_OPEN_FOR_BACKUP_INTENT"},
		{0x00008000, "FILE_NO_COMPRESSION"},
		{0x00100000, "FILE_RESERVE_OPFILTER"},
		{0x00200000, "FILE_OPEN_REPARSE_POINT"},
		{0x00400000, "FILE_OPEN_NO_RECALL"},
		{0x00800000, "FILE_OPEN_FOR_FREE_SPACE_QUERY"},
		{0x00ffffff, "FILE_VALID_OPTION_FLAGS"},
		{0x00000032, "FILE_VALID_PIPE_OPTION_FLAGS"},
		{0x00000032, "FILE_VALID_MAILSLOT_OPTION_FLAGS"},
		{0x00000036, "FILE_VALID_SET_FLAGS"}
	};
}