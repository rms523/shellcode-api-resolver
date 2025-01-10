#include <Windows.h>
#include <stdio.h>

extern int get_kernel32_address();
extern int fetch_getprocaddress(int);

int main()
{
	int kernel32_address, getproc_address;
	FARPROC get_computername;
	char compname[MAX_PATH] = {0};
	DWORD size = MAX_PATH;
	
	kernel32_address = get_kernel32_address();
	
	printf("kernel32 address is %x\r\n", kernel32_address);
	
	getproc_address = fetch_getprocaddress(kernel32_address);
	
	printf("GetProcAddress is at %x\r\n", getproc_address);
	
	get_computername = ((FARPROC (__stdcall *) (HMODULE, LPCSTR)) getproc_address)((HMODULE)kernel32_address,"GetComputerNameA");
	
	((BOOL (__stdcall *) (LPSTR, LPDWORD)) get_computername)(compname, &size);
	
	printf("Computer name is %s", compname);
}
