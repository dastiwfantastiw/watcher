#include "memory.h"

#pragma init_seg(compiler) // override 'new' and 'delete' must be done first

namespace memory
{
	HANDLE             hHeap = HeapCreate(NULL, NULL, NULL);
	fRtlAllocateHeap   RtlAllocateHeap = reinterpret_cast<fRtlAllocateHeap>(GetProcAddress(LoadLibraryA("ntdll"), "RtlAllocateHeap"));
	fRtlFreeHeap       RtlFreeHeap = reinterpret_cast<fRtlFreeHeap>(GetProcAddress(LoadLibraryA("ntdll"), "RtlFreeHeap"));
	fRtlReAllocateHeap RtlReAllocateHeap = reinterpret_cast<fRtlReAllocateHeap>(GetProcAddress(LoadLibraryA("ntdll"), "RtlReAllocateHeap"));
	fRtlLockHeap       RtlLockHeap = reinterpret_cast<fRtlLockHeap>(GetProcAddress(LoadLibraryA("ntdll"), "RtlLockHeap"));
	fRtlUnlockHeap     RtlUnlockHeap = reinterpret_cast<fRtlUnlockHeap>(GetProcAddress(LoadLibraryA("ntdll"), "RtlUnlockHeap"));

	std::map<ACCESS_MASK, const char*> AllocationMasks =
	{
		{0x00001000, "MEM_COMMIT"},
		{0x00002000, "MEM_RESERVE"},
		{0x00004000, "MEM_REPLACE_PLACEHOLDER"},
		{0x00040000, "MEM_RESERVE_PLACEHOLDER"},
		{0x00080000, "MEM_RESET"},
		{0x00100000, "MEM_TOP_DOWN"},
		{0x00200000, "MEM_WRITE_WATCH"},
		{0x00400000, "MEM_PHYSICAL"},
		{0x00800000, "MEM_ROTATE"},
		{0x00800000, "MEM_DIFFERENT_IMAGE_BASE_OK"},
		{0x01000000, "MEM_RESET_UNDO"},
		{0x20000000, "MEM_LARGE_PAGES"},
		{0x80000000, "MEM_4MB_PAGES"},
		{0x20400000, "MEM_64K_PAGES"},
		{0x00000001, "MEM_UNMAP_WITH_TRANSIENT_BOOST"},
		{0x00000001, "MEM_COALESCE_PLACEHOLDERS"},
		{0x00000002, "MEM_PRESERVE_PLACEHOLDER"},
		{0x00004000, "MEM_DECOMMIT"},
		{0x00008000, "MEM_RELEASE"},
		{0x00010000, "MEM_FREE"}
	};

	std::map<ACCESS_MASK, const char*> ProtectionMasks =
	{
		{0x01, "PAGE_NOACCESS"},
		{0x02, "PAGE_READONLY"},
		{0x04, "PAGE_READWRITE"},
		{0x08, "PAGE_WRITECOPY"},
		{0x10, "PAGE_EXECUTE"},
		{0x20, "PAGE_EXECUTE_READ"},
		{0x40, "PAGE_EXECUTE_READWRITE"},
		{0x80, "PAGE_EXECUTE_WRITECOPY"},
		{0x100, "PAGE_GUARD"},
		{0x200, "PAGE_NOCACHE"},
		{0x400, "PAGE_WRITECOMBINE"},
		{0x0800, "PAGE_GRAPHICS_NOACCESS"},
		{0x1000, "PAGE_GRAPHICS_READONLY"},
		{0x2000, "PAGE_GRAPHICS_READWRITE"},
		{0x4000, "PAGE_GRAPHICS_EXECUTE"},
		{0x8000, "PAGE_GRAPHICS_EXECUTE_READ"},
		{0x10000, "PAGE_GRAPHICS_EXECUTE_READWRITE"},
		{0x20000, "PAGE_GRAPHICS_COHERENT"},
		{0x40000, "PAGE_GRAPHICS_NOCACHE"},
		{0x80000000, "PAGE_ENCLAVE_THREAD_CONTROL"},
		{0x40000000, "PAGE_TARGETS_INVALID"},
		{0x20000000, "PAGE_ENCLAVE_UNVALIDATED"},
		{0x10000000 | 0, "PAGE_ENCLAVE_DECOMMIT"},
		{0x10000000 | 1, "PAGE_ENCLAVE_SS_FIRST"},
		{0x10000000 | 2, "PAGE_ENCLAVE_SS_REST"}
	};
}

void* memory::Alloc(size_t Size)
{
	return RtlAllocateHeap(hHeap, HEAP_ZERO_MEMORY, Size);
}

void* memory::ReAlloc(void* Mem, size_t Size)
{
	return RtlReAllocateHeap(hHeap, HEAP_ZERO_MEMORY, Mem, Size);
}

bool memory::Free(void* Mem)
{
	return RtlFreeHeap(hHeap, NULL, Mem);
}

bool memory::HeapLock()
{
	return RtlLockHeap(hHeap);
}

bool memory::HeapUnlock()
{
	return RtlUnlockHeap(hHeap);
}

bool memory::IsBadReadPointer(void* Pointer, SIZE_T& AvailableSize)
{
	if (!Pointer)
	{
		return true;
	}

	MEMORY_BASIC_INFORMATION memBasic;

	if (VirtualQuery(Pointer, &memBasic, sizeof(memBasic)))
	{
		if ((memBasic.Protect & PAGE_GUARD) ||
			(memBasic.Protect & PAGE_NOACCESS))
		{
			return true;
		}

		if (((memBasic.Protect & PAGE_READONLY)          ||
			 (memBasic.Protect & PAGE_READWRITE)         ||
			 (memBasic.Protect & PAGE_WRITECOPY)         ||
			 (memBasic.Protect & PAGE_EXECUTE_READ)	     ||
			 (memBasic.Protect & PAGE_EXECUTE_READWRITE) ||
			 (memBasic.Protect & PAGE_EXECUTE_WRITECOPY)))
		{
			AvailableSize = (reinterpret_cast<SIZE_T>(memBasic.BaseAddress) + memBasic.RegionSize) - reinterpret_cast<SIZE_T>(Pointer);
			return false;
		}

	}
	return true;
}

bool memory::ReadMemory(HANDLE ProcessHandle, LPCVOID Address, LPVOID Buffer, SIZE_T Size)
{
	return ReadProcessMemory(ProcessHandle, Address, Buffer, Size, NULL);
}

bool memory::WriteMemory(HANDLE ProcessHandle, LPVOID Address, LPVOID Buffer, SIZE_T Size)
{
	return WriteProcessMemory(ProcessHandle, Address, Buffer, Size, NULL);
}

void* __cdecl operator new(size_t Size)
{
	return memory::RtlAllocateHeap(memory::hHeap, NULL, Size);
}

void __cdecl operator delete(void* Mem)
{
	memory::RtlFreeHeap(memory::hHeap, NULL, Mem);
}