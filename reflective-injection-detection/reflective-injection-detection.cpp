#include "stdafx.h"
#include <windows.h>
#include <tlhelp32.h>
#include "reflective-injection-detection.h"

BOOL moduleRecord::isIn(LPVOID lpAddress)
{
	if (this->lpStartAddress <= lpAddress && lpAddress < this->lpEndAddress)
	{
		return true;
	}
	else
	{
		return false;
	}
}
moduleList::moduleList()
{
	this->lpModuleList = VirtualAlloc(NULL, 16384, MEM_COMMIT, PAGE_READWRITE);
}
BOOL moduleList::addModule(MODULEENTRY32 *me32)
{
	pmoduleRecord pmr = (pmoduleRecord)((DWORD)this->lpModuleList + (dwSize * sizeof(moduleRecord)));
	pmr->lpStartAddress = me32->modBaseAddr;
	pmr->lpEndAddress = me32->modBaseAddr + me32->dwSize;
	this->dwSize++;
	return true;
}
BOOL moduleList::searchModule(LPVOID lpModuleAddress)
{
	if (!lpModuleAddress) // if lpModuleAddress is 0x00000000 return true and don't consider the page as injected
	{
		return true;
	}
	if (this->dwSize > 0)
	{
		pmoduleRecord pmr = (pmoduleRecord)this->lpModuleList;
		do
		{
			if (pmr->isIn(lpModuleAddress))
			{
				return true;
			}
			pmr++;
		} while (pmr->lpStartAddress != 0);
		return false;
	}
	else
	{
		return false;
	}
}
BOOL moduleList::clear()
{
	ZeroMemory(this->lpModuleList, ALLOC_SIZE);
	this->dwSize = 0;
	return true;
}

DWORD dwPageAmount = 0;
LPVOID lpExecutableBuffer;

int main(void)
{
	DWORD dwLargePageMin = GetLargePageMinimum();
	int a = GetLastError();
	DWORD dwAllocSize = dwLargePageMin * 10;
	lpExecutableBuffer = VirtualAlloc(NULL, dwAllocSize, MEM_COMMIT, PAGE_READWRITE);
	GetProcessList();
	VirtualFree(lpExecutableBuffer, dwAllocSize, MEM_RELEASE);
	return 0;
}
BOOL isDataDiverse(LPVOID lpAddress, DWORD dwPageSize)
{
	LPBYTE lpPointer = (LPBYTE)lpAddress;
	LPBYTE lpStopPointer = (LPBYTE)((DWORD)lpAddress + dwPageSize - 1);
	BYTE bByte = *lpPointer;
	do
	{
		lpPointer++;
	} while (bByte == *lpPointer && lpPointer != lpStopPointer);
	if (lpPointer == lpStopPointer)
	{
		return false;
	}
	else
	{
		return true;
	}
}
BOOL isPageValidCode(LPVOID lpAddress, DWORD dwPageSize)
{
	// insert checks for code validity
	if (!isDataDiverse(lpAddress, dwPageSize))
	{
		return false;
	}

}
DWORD calcLargePageAlloc(DWORD dwLargePageMin, DWORD dwSizeOfPage)
{
	while (dwLargePageMin < dwSizeOfPage)
	{
		dwLargePageMin += dwLargePageMin;
	}
	return dwLargePageMin;
}
BOOL GetProcessList()
{
	HANDLE hProcessSnap;
	HANDLE hProcess;
	PROCESSENTRY32 pe32;
	moduleList ml = moduleList();

	// Take a snapshot of all processes in the system.
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		return(FALSE);
	}

	// Set the size of the structure before using it.
	pe32.dwSize = sizeof(PROCESSENTRY32);

	// Retrieve information about the first process,
	// and exit if unsuccessful
	if (!Process32First(hProcessSnap, &pe32))
	{
		CloseHandle(hProcessSnap);          // clean the snapshot object
		return(FALSE);
	}

	// Now walk the snapshot of processes, and
	// display information about each process in turn
	do
	{
		ListProcessModules(pe32.th32ProcessID, &ml);

	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	printf("%d pages found.\n", dwPageAmount);
	return TRUE;
}
BOOL ListProcessModules(DWORD dwPID, pmoduleList pml)
{
	HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
	MODULEENTRY32 me32;

	// Take a snapshot of all modules in the specified process.
	hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID);
	if (hModuleSnap == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}
	//lpModuleList
	// Set the size of the structure before using it.
	me32.dwSize = sizeof(MODULEENTRY32);

	// Retrieve information about the first module,
	// and exit if unsuccessful
	if (!Module32First(hModuleSnap, &me32))
	{
		CloseHandle(hModuleSnap);           // clean the snapshot object
		return FALSE;
	}

	// Now walk the module list of the process,
	// and display information about each module
	do
	{
		pml->addModule(&me32);
	} while (Module32Next(hModuleSnap, &me32));
	retrievePagesAndCrossValidate(pml, dwPID);
	pml->clear();
	CloseHandle(hModuleSnap);
	return TRUE;
}
BOOL retrievePagesAndCrossValidate(pmoduleList pml, DWORD dwPid)
{
	_MEMORY_BASIC_INFORMATION mbi;
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
	if (!hProcess || hProcess == INVALID_HANDLE_VALUE)
	{
		return false;
	}
	LPVOID lpAddress = 0;
	DWORD dwSize;
	do
	{
		dwSize = VirtualQueryEx(hProcess, lpAddress, &mbi, sizeof(mbi));
		if (!pml->searchModule(mbi.BaseAddress))
		{
			
			if ((mbi.AllocationProtect == PAGE_EXECUTE_READWRITE) && (mbi.State == MEM_COMMIT || mbi.State == MEM_RESERVE | MEM_COMMIT) && (mbi.Type == MEM_PRIVATE))
			{
				if (mbi.Protect == NULL)
				{
					printf("no access to memory at 0x%08x - 0x%08x in %d\n", mbi.BaseAddress, ((DWORD)mbi.BaseAddress + mbi.RegionSize), dwPid);
					lpAddress = LPVOID((DWORD)mbi.BaseAddress + mbi.RegionSize);
					continue;
				}
				else if (mbi.Protect != PAGE_EXECUTE_READWRITE && mbi.Protect != PAGE_EXECUTE_READ)
				{
					lpAddress = LPVOID((DWORD)mbi.BaseAddress + mbi.RegionSize);
					continue;
				}
				char cHead[3] = { 0x00 };
				DWORD dwBytesRead;
				ReadProcessMemory(hProcess, mbi.BaseAddress, &cHead, 2, &dwBytesRead);
				char cDumpFile[MAX_PATH + 1] = { 0x00 };
				if (strcmp(cHead, "MZ") == 0)
				{
					printf("PE header found at 0x%08x in %d.\n", mbi.BaseAddress, dwPid);
					_snprintf_s(cDumpFile, MAX_PATH + 1, "%d at 0x%08x contains MZ.bin", dwPid, mbi.BaseAddress);
				}
				else
				{
					_snprintf_s(cDumpFile, MAX_PATH + 1, "%d at 0x%08x.bin", dwPid, mbi.BaseAddress);
				}
				if (mbi.RegionSize > KB)
				{
					DWORD dwLeftToRead = mbi.RegionSize;
					DWORD dwAmountRead = 0;
					DWORD dwAmountToRead;
					if (dwLeftToRead > KB)
					{
						dwAmountToRead = KB;
					}
					else
					{
						dwAmountToRead = dwLeftToRead;
					}
					while (dwLeftToRead)
					{
						dwAmountRead = (mbi.RegionSize - dwLeftToRead);
						if (!ReadProcessMemory(hProcess, (LPVOID)((DWORD)mbi.BaseAddress + dwAmountRead), (LPVOID)((DWORD)lpExecutableBuffer + dwAmountRead), dwAmountToRead, &dwBytesRead))
						{
							printf("error %d in reading process %d\n", GetLastError(), dwPid);
							break;
						}
						dwLeftToRead -= dwBytesRead;
					}
				}
				else
				{
					if (!ReadProcessMemory(hProcess, mbi.BaseAddress, lpExecutableBuffer, mbi.RegionSize, &dwBytesRead))
					{
						printf("error %d in reading process %d\n", GetLastError(), dwPid);
					}
				}
				if (!isPageValidCode(lpExecutableBuffer, mbi.RegionSize))
				{
					lpAddress = LPVOID((DWORD)mbi.BaseAddress + mbi.RegionSize);
					continue;
				}
				HANDLE hFile = CreateFileA(cDumpFile, GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
				WriteFile(hFile, lpExecutableBuffer, mbi.RegionSize, &dwBytesRead, NULL);
				CloseHandle(hFile);
				//VirtualFree(lpExecutableBuffer, mbi.RegionSize, MEM_RELEASE);
				dwPageAmount++;
			}
		}
		lpAddress = LPVOID((DWORD)mbi.BaseAddress + mbi.RegionSize);
	} while (dwSize);
	CloseHandle(hProcess);
	return false;
}
