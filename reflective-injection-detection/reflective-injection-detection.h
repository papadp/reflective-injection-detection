#include "Windows.h"

#define ALLOC_SIZE		16384
#define KB			1024

typedef struct moduleRecord
{
	LPVOID lpStartAddress;
	LPVOID lpEndAddress;
	BOOL isIn(LPVOID lpAddress);
}*pmoduleRecord;
typedef struct moduleList
{
	moduleList();
	BOOL addModule(MODULEENTRY32 *me32);
	BOOL searchModule(LPVOID lpModuleAddress);
	BOOL clear();
	LPVOID lpModuleList;
	DWORD dwSize = 0;
}*pmoduleList;

//  Forward declarations:
BOOL GetProcessList();
BOOL ListProcessModules(DWORD dwPID, pmoduleList pml);
BOOL retrievePagesAndCrossValidate(pmoduleList pml, DWORD dwPid);
BOOL isPageValidCode(LPVOID lpAddress, DWORD dwPageSize);