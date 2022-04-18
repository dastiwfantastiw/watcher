#pragma once
#include "pe_format.h"
#include <winternl.h>
#include <string>

namespace tools
{
	typedef int(_cdecl* f_vsnprintf)(char* const Buffer, const size_t BufferCount, const char* const Format, va_list ArgList);
	typedef int(_cdecl* f__snprintf)(char* const Buffer, const size_t BufferCount, const char* const Format, ...);

	typedef enum _OBJECT_INFORMATION_CLASS 
	{
		ObjectBasicInformation,
		ObjectNameInformation,
		ObjectTypeInformation,
		ObjectAllInformation,
		ObjectDataInformation
	} OBJECT_INFORMATION_CLASS, * POBJECT_INFORMATION_CLASS;

	typedef struct _OBJECT_BASIC_INFORMATION 
	{
		ULONG                   Attributes;
		ACCESS_MASK             DesiredAccess;
		ULONG                   HandleCount;
		ULONG                   ReferenceCount;
		ULONG                   PagedPoolUsage;
		ULONG                   NonPagedPoolUsage;
		ULONG                   Reserved[3];
		ULONG                   NameInformationLength;
		ULONG                   TypeInformationLength;
		ULONG                   SecurityDescriptorLength;
		LARGE_INTEGER           CreationTime;
	} OBJECT_BASIC_INFORMATION, * POBJECT_BASIC_INFORMATION;

	typedef struct _OBJECT_NAME_INFORMATION
	{
		UNICODE_STRING          Name;
		WCHAR                   NameBuffer[1];
	} OBJECT_NAME_INFORMATION, * POBJECT_NAME_INFORMATION;

	typedef enum _POOL_TYPE
	{
		NonPagedPool = 0,
		PagedPool = 1,
		NonPagedPoolMustSucceed = 2,
		DontUseThisType = 3,
		NonPagedPoolCacheAligned = 4,
		PagedPoolCacheAligned = 5,
		NonPagedPoolCacheAlignedMustS = 6,
		MaxPoolType = 7,
		NonPagedPoolSession = 32,
		PagedPoolSession = 33,
		NonPagedPoolMustSucceedSession = 34,
		DontUseThisTypeSession = 35,
		NonPagedPoolCacheAlignedSession = 36,
		PagedPoolCacheAlignedSession = 37,
		NonPagedPoolCacheAlignedMustSSession = 38
	} POOL_TYPE;

	typedef struct _OBJECT_TYPE_INFORMATION 
	{
		UNICODE_STRING          TypeName;
		ULONG                   TotalNumberOfHandles;
		ULONG                   TotalNumberOfObjects;
		WCHAR                   Unused1[8];
		ULONG                   HighWaterNumberOfHandles;
		ULONG                   HighWaterNumberOfObjects;
		WCHAR                   Unused2[8];
		ACCESS_MASK             InvalidAttributes;
		GENERIC_MAPPING         GenericMapping;
		ACCESS_MASK             ValidAttributes;
		BOOLEAN                 SecurityRequired;
		BOOLEAN                 MaintainHandleCount;
		USHORT                  MaintainTypeList;
		POOL_TYPE               PoolType;
		ULONG                   DefaultPagedPoolCharge;
		ULONG                   DefaultNonPagedPoolCharge;
	} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

	typedef struct _OBJECT_ALL_INFORMATION 
	{
		ULONG                   NumberOfObjectsTypes;
		OBJECT_TYPE_INFORMATION ObjectTypeInformation[1];
	} OBJECT_ALL_INFORMATION, * POBJECT_ALL_INFORMATION;

	typedef struct _OBJECT_DATA_INFORMATION 
	{
		BOOLEAN                 InheritHandle;
		BOOLEAN                 ProtectFromClose;
	} OBJECT_DATA_INFORMATION, * POBJECT_DATA_INFORMATION;

	typedef enum _PROCESSINFOCLASS
	{
		ProcessBasicInformation,
		ProcessQuotaLimits,
		ProcessIoCounters,
		ProcessVmCounters,
		ProcessTimes,
		ProcessBasePriority, 
		ProcessRaisePriority,
		ProcessDebugPort,
		ProcessExceptionPort,
		ProcessAccessToken, 
		ProcessLdtInformation,
		ProcessLdtSize,
		ProcessDefaultHardErrorMode,
		ProcessIoPortHandlers,
		ProcessPooledUsageAndLimits,
		ProcessWorkingSetWatch,
		ProcessUserModeIOPL,
		ProcessEnableAlignmentFaultFixup,
		ProcessPriorityClass,
		ProcessWx86Information,
		ProcessHandleCount,
		ProcessAffinityMask,
		ProcessPriorityBoost,
		ProcessDeviceMap,
		ProcessSessionInformation,
		ProcessForegroundInformation,
		ProcessWow64Information,
		ProcessImageFileName,
		ProcessLUIDDeviceMapsEnabled,
		ProcessBreakOnTermination,
		ProcessDebugObjectHandle,
		ProcessDebugFlags,
		ProcessHandleTracing,
		ProcessIoPriority,
		ProcessExecuteFlags,
		ProcessResourceManagement,
		ProcessCookie,
		ProcessImageInformation,
		ProcessCycleTime, 
		ProcessPagePriority,
		ProcessInstrumentationCallback,
		ProcessThreadStackAllocation,
		ProcessWorkingSetWatchEx, 
		ProcessImageFileNameWin32,
		ProcessImageFileMapping,
		ProcessAffinityUpdateMode,
		ProcessMemoryAllocationMode,
		ProcessGroupInformation,
		ProcessTokenVirtualizationEnabled,
		ProcessConsoleHostProcess,
		ProcessWindowInformation, 
		ProcessHandleInformation,
		ProcessMitigationPolicy,
		ProcessDynamicFunctionTableInformation,
		ProcessHandleCheckingMode,
		ProcessKeepAliveCount,
		ProcessRevokeFileHandles, 
		ProcessWorkingSetControl, 
		ProcessHandleTable,
		ProcessCheckStackExtentsMode,
		ProcessCommandLineInformation, 
		ProcessProtectionInformation,
		ProcessMemoryExhaustion,
		ProcessFaultInformation,
		ProcessTelemetryIdInformation,
		ProcessCommitReleaseInformation,
		ProcessDefaultCpuSetsInformation,
		ProcessAllowedCpuSetsInformation,
		ProcessReserved1Information,
		ProcessReserved2Information,
		ProcessSubsystemProcess,
		ProcessJobMemoryInformation,
		MaxProcessInfoClass
	} PROCESSINFOCLASS;

	typedef enum _FILE_INFORMATION_CLASS 
	{
		FileDirectoryInformation = 1,
		FileFullDirectoryInformation,
		FileBothDirectoryInformation,
		FileBasicInformation,
		FileStandardInformation,
		FileInternalInformation,
		FileEaInformation,
		FileAccessInformation,
		FileNameInformation,
		FileRenameInformation,
		FileLinkInformation,
		FileNamesInformation,
		FileDispositionInformation,
		FilePositionInformation,
		FileFullEaInformation,
		FileModeInformation,
		FileAlignmentInformation,
		FileAllInformation,
		FileAllocationInformation,
		FileEndOfFileInformation,
		FileAlternateNameInformation,
		FileStreamInformation,
		FilePipeInformation,
		FilePipeLocalInformation,
		FilePipeRemoteInformation,
		FileMailslotQueryInformation,
		FileMailslotSetInformation,
		FileCompressionInformation,
		FileCopyOnWriteInformation,
		FileCompletionInformation,
		FileMoveClusterInformation,
		FileQuotaInformation,
		FileReparsePointInformation,
		FileNetworkOpenInformation,
		FileObjectIdInformation,
		FileTrackingInformation,
		FileOleDirectoryInformation,
		FileContentIndexInformation,
		FileInheritContentIndexInformation,
		FileOleInformation,
		FileMaximumInformation
	} FILE_INFORMATION_CLASS, * PFILE_INFORMATION_CLASS;

	typedef struct _FILE_BASIC_INFORMATION 
	{
		LARGE_INTEGER           CreationTime;
		LARGE_INTEGER           LastAccessTime;
		LARGE_INTEGER           LastWriteTime;
		LARGE_INTEGER           ChangeTime;
		ULONG                   FileAttributes;
	} FILE_BASIC_INFORMATION, * PFILE_BASIC_INFORMATION;

	typedef struct _FILE_NAME_INFORMATION 
	{
		ULONG                   FileNameLength;
		WCHAR                   FileName[MAX_PATH * 2];
	} FILE_NAME_INFORMATION, * PFILE_NAME_INFORMATION;

	typedef struct _INITIAL_TEB {
		VOID* StackBase;
		VOID* StackLimit;
		VOID* StackCommit;
		VOID* StackCommitMax;
		VOID* StackReserved;
	} INITIAL_TEB, * PINITIAL_TEB;

	typedef NTSTATUS
	(NTAPI* fNtQueryInformationFile)(
		HANDLE               FileHandle,
		PIO_STATUS_BLOCK    IoStatusBlock,
		PVOID               FileInformation,
		ULONG                Length,
		FILE_INFORMATION_CLASS FileInformationClass);

	extern fNtQueryInformationFile NtQueryInformationFile;
	extern f_vsnprintf __vsnprintf;
	extern f__snprintf __snprintf;

	bool ModulePathToName(char* SourceString, std::string& DestinationString);
	bool UnicodeToAscii(wchar_t* SourceWideString, std::string& DestinationString);
	int  FormatString(char* Buffer, size_t Size, const char* FormatString, ...);

	NTSTATUS QueryObject(HANDLE Object, tools::OBJECT_INFORMATION_CLASS Class, LPVOID OutputData, ULONG DataSize, ULONG* RetSize);
	NTSTATUS QueryInformationProcess(HANDLE ProcessHandle, tools::PROCESSINFOCLASS Class, LPVOID OutputData, ULONG DataSize, ULONG* RetSize);
	NTSTATUS QueryInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, LPVOID OutputData, ULONG DataSize, tools::FILE_INFORMATION_CLASS Class);

	std::string ConstMaskToString(ACCESS_MASK Mask, std::map<ACCESS_MASK, const char*>& SourceData);
	std::string ConstToString(DWORD Const, std::map<DWORD, const char*>& SourceData);

	std::string HexBuffer(void* Buffer, int Size);
}