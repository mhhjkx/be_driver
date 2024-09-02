

#include <driver/xorstr.h>
#include <system/funcs.h>
#include <core/hook.h>
#include <driver/include.h>

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT, PUNICODE_STRING)
{
	RTL_OSVERSIONINFOW info = { 0 };
	uintptr_t win32kbase = system::get_system_module(XORS(L"win32kbase.sys"));

	if (!info.dwBuildNumber)
		RtlGetVersion(&info);

	if (!win32kbase)
		return STATUS_UNSUCCESSFUL;

	if (info.dwBuildNumber >= 22000)
	{
		core_hook::fptr_addr = system::find_pattern(win32kbase, XORS("\x74\x24\x48\x8B\x84\x24\x90\x00\x00\x00\x44\x8B\xCE"), XORS("xxxxxxx???xxx"));
		if (!core_hook::fptr_addr)
			return STATUS_UNSUCCESSFUL;
		*(void**)&core_hook::o_function_qword_1 = InterlockedExchangePointer((void**)dereference((core_hook::fptr_addr - 0xA)), (void*)core_hook::hooked_fptr);
		
		return STATUS_SUCCESS;
	}
	core_hook::fptr_addr = system::find_pattern(win32kbase, XORS("\x74\x20\x48\x8B\x44\x24\x00\x44\x8B\xCF"), XORS("xxxxxx?xxx"));
	if (!core_hook::fptr_addr)
		return STATUS_UNSUCCESSFUL;
	*(void**)&core_hook::o_function_qword_1 = InterlockedExchangePointer((void**)dereference((core_hook::fptr_addr - 0xA)), (void*)core_hook::hooked_fptr);

	return STATUS_SUCCESS;
}