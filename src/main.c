#include "main.h"
#include "clistview.h"

#if defined _M_IX86
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='x86' publicKeyToken='6595b64144ccf1df' language='*'\"")
#elif defined _M_IA64
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='ia64' publicKeyToken='6595b64144ccf1df' language='*'\"")
#elif defined _M_X64
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='amd64' publicKeyToken='6595b64144ccf1df' language='*'\"")
#else
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#endif

static CListView *lvProcesses = NULL;
static CListView *lvModules = NULL;

static SYSTEM_INFO g_SysInfo = {0};

static BOOL AdjustPrivilege(LPCSTR p_Priviledge, BOOL fEnable)
{
	BOOL fOk = FALSE;	// Assume function fails
	HANDLE hToken;

	// Try to open this process's access token
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		TOKEN_PRIVILEGES tp;
		tp.PrivilegeCount = 1;
		LookupPrivilegeValue(NULL, p_Priviledge, &tp.Privileges[0].Luid);
		tp.Privileges[0].Attributes = fEnable ? SE_PRIVILEGE_ENABLED : 0;
		AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
		fOk = (GetLastError() == ERROR_SUCCESS);
		CloseHandle(hToken);
	}
	return (fOk);
}

void ListView_InsertColumns(HWND hListV, LVCOLUMN *lpColumn, size_t nCount)
{
	for (size_t i = 0; i < nCount; i++)
		ListView_InsertColumn(hListV, i, &lpColumn[i]);
}

void GetWin32Path(CHAR *NTPath, CHAR *ps_DosPath)
{
	CHAR Drives[300];
	GetLogicalDriveStrings(300, Drives);

	CHAR *Drv = Drives;
	while (Drv[0])
	{
		CHAR *Next = Drv + strlen(Drv) + 1;

		Drv[2] = 0;	// the backslash is not allowed for QueryDosDevice()

		CHAR NtVolume[1000];
		NtVolume[0] = 0;

		// may return multiple strings!
		// returns very weird strings for network shares
		QueryDosDevice(Drv, NtVolume, sizeof(NtVolume));

		int s32_Len = (int)strlen(NtVolume);
		if (s32_Len > 0 && _strnicmp(NTPath, NtVolume, s32_Len) == 0)
		{
			strcpy(ps_DosPath, Drv);
			strcat(ps_DosPath, &NTPath[s32_Len]);
			return 0;
		}

		Drv = Next;
	}
}

void EnumProcess(void)
{
	SHFILEINFO FileInfo;
	size_t nCount;
	CHAR szPid[PVOID_HEX_SIZE], szIBase[PVOID_HEX_SIZE], szISize[PVOID_HEX_SIZE];

	ULONG uSysInfoSize = 0;
	PSYSTEM_PROCESSES lpProcInfo = NULL, lpProcInfoMem = NULL;

	uSelectedPid = 0;
	CListView_Clear(lvProcesses);
	CListView_Clear(lvModules);

	ImageList_RemoveAll(himl);

	// Запрашиваем необходимый размер под структуру
	ULONG ret = ZwQuerySystemInformation(SystemProcessesAndThreadsInformation, NULL, 0, &uSysInfoSize);
	if (ret != STATUS_INFO_LENGTH_MISMATCH)
		return;

	// Получаем информацию о процессах
	lpProcInfoMem = lpProcInfo = (PSYSTEM_PROCESSES)VirtualAlloc(NULL, uSysInfoSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	ret = ZwQuerySystemInformation(SystemProcessesAndThreadsInformation, lpProcInfo, uSysInfoSize, &uSysInfoSize);
	if (ret != STATUS_INFO_LENGTH_MISMATCH)
	{
		nCount = 0;
		while (lpProcInfo->NextEntryDelta)
		{
			// Исключаем из списка Idle процесс
			if (!lpProcInfo->ProcessId || lpProcInfo->ProcessId == 4)
			{
				lpProcInfo = (PSYSTEM_PROCESSES) ((ULONG_PTR)lpProcInfo + lpProcInfo->NextEntryDelta);
				continue;
			}

			snprintf(szPid, PVOID_HEX_SIZE, "%u", lpProcInfo->ProcessId);
			memset(szIBase, 0, PVOID_HEX_SIZE);
			memset(szISize, 0, PVOID_HEX_SIZE);

			UINT itemMask = LVIF_TEXT | LVIF_IMAGE;
			LVITEM li[] = {
				{itemMask, nCount, 0, 0, 0, NULL, 0, nCount, 0, 0},
				{itemMask, nCount, 1, 0, 0, szPid, 0, -1, 0, 0},
				{itemMask, nCount, 2, 0, 0, szIBase, 0, -1, 0, 0},
				{itemMask, nCount, 3, 0, 0, szISize, 0, -1, 0, 0},
			};

			// unicode -> asciiz
			CHAR *lpName = VirtualAlloc(NULL, lpProcInfo->ProcessName.Length+100, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			//WideCharToMultiByte(CP_ACP, 0, lpProcInfo->ProcessName.Buffer, lpProcInfo->ProcessName.Length, lpName, lpProcInfo->ProcessName.Length, NULL, NULL);
			wcstombs(lpName, lpProcInfo->ProcessName.Buffer, lpProcInfo->ProcessName.Length);
			li[0].pszText = lpName;

			HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ , TRUE, lpProcInfo->ProcessId);
			if (hProcess == NULL)
			{
				CListView_AddToImageList(lvProcesses, LoadIcon(NULL, IDI_ERROR));
				CListView_AppendLine(lvProcesses, (LVITEM*)&li);
				VirtualFree(lpName, 0, MEM_RELEASE);
				lpProcInfo = (PSYSTEM_PROCESSES) ((ULONG_PTR)lpProcInfo + lpProcInfo->NextEntryDelta);
				nCount++;
				continue;
			}

			BOOL bWow64 = FALSE;
			IsWow64Process(hProcess, &bWow64);

#ifdef _WIN32
			if (g_SysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL || bWow64){
#endif
			// Получаем информацию о процессе
			PROCESS_BASIC_INFORMATION BasicInfo = {0};
			ULONG ret = ZwQueryInformationProcess(hProcess, ProcessBasicInformation, &BasicInfo, sizeof(BasicInfo), NULL);
			if (ret != 0)
			{
				CListView_AddToImageList(lvProcesses, LoadIcon(NULL, IDI_ERROR));
				CListView_AppendLine(lvProcesses, (LVITEM*)&li);
				CloseHandle(hProcess);
				VirtualFree(lpName, 0, MEM_RELEASE);
				lpProcInfo = (PSYSTEM_PROCESSES) ((ULONG_PTR)lpProcInfo + lpProcInfo->NextEntryDelta);
				nCount++;
				continue;
			}

			PPEB lpPeb = BasicInfo.PebBaseAddress;
			struct _PEB_LDR_DATA *lpLdrPtr = NULL;
			SIZE_T dwRead = 0;
			ReadProcessMemory(hProcess, (LPVOID)((DWORD)lpPeb + offsetof(PEB, Ldr)), &lpLdrPtr, sizeof(lpLdrPtr), &dwRead);

			struct _PEB_LDR_DATA Ldr;
			ReadProcessMemory(hProcess, lpLdrPtr, &Ldr, sizeof(Ldr), &dwRead);

			LDR_MODULE module = {0};
			ReadProcessMemory(hProcess, Ldr.InLoadOrderModuleList.Flink, &module, sizeof(module), &dwRead);
			snprintf(szIBase, PVOID_HEX_SIZE, "%P", module.BaseAddress);
			snprintf(szISize, PVOID_HEX_SIZE, "%P", module.SizeOfImage);

#ifdef _WIN32
			}
#endif

			/*CHAR *lpNameA = NULL;
			WCHAR *lpNameW = NULL;
			if (module.FullDllName.Length)
			{
				lpNameA = malloc(module.FullDllName.MaximumLength+100);
				lpNameW = malloc(module.FullDllName.MaximumLength+100);
				if (lpNameA && lpNameW) {
					ReadProcessMemory(hProcess, module.FullDllName.Buffer, lpNameW, module.FullDllName.MaximumLength, &dwRead);
					wcstombs(lpNameA, lpNameW, module.FullDllName.MaximumLength);
					if (strlen(lpNameA))
						li[0].pszText = lpNameA;
				}
			}
			else
			{
				CHAR buf[MAX_PATH], buf2[MAX_PATH];
				GetProcessImageFileName(hProcess, buf, MAX_PATH);
				GetWin32Path(buf, buf2);
				MessageBox(0, buf2 ,"" ,0);
			}*/

			CHAR buf[MAX_PATH*4], buf2[MAX_PATH*4];
			GetProcessImageFileName(hProcess, buf, MAX_PATH*4);
			GetWin32Path(buf, buf2);
			li[0].pszText = buf2;

			// Получаем главную иконку процесса
			memset((LPVOID) &FileInfo, 0, sizeof(FileInfo));
			SHGetFileInfo(li[0].pszText, 0, &FileInfo, sizeof(FileInfo), SHGFI_SMALLICON | SHGFI_ICON);

			// Если иконку получить не удалось, загружаем иконку ошибки
			HICON hIcon = FileInfo.hIcon;	//ExtractIcon(ghInst, pModuleInfo[0].ImageName, 0);
			if (!hIcon)
				hIcon = LoadIcon(NULL, IDI_ERROR);
			CListView_AddToImageList(lvProcesses, hIcon);
			DestroyIcon(hIcon);

			if (bWow64)
				strcat(li[0].pszText, " *");
			CListView_AppendLine(lvProcesses, (LVITEM*)&li);

			//free(lpNameA);
			//free(lpNameW);

			/*
			// Пытаемся получить список модулей процесса
			PDEBUG_BUFFER pRtlBuffer = RtlCreateQueryDebugBuffer(0, FALSE);
			if (pRtlBuffer)
			{
				ret = RtlQueryProcessDebugInformation(lpProcInfo->ProcessId, PDI_MODULES, pRtlBuffer);

				if (!ret && pRtlBuffer->ModuleInformation)
				{
					PDEBUG_MODULE_INFORMATION pModuleInfo = (PDEBUG_MODULE_INFORMATION) ((ULONG_PTR)pRtlBuffer->ModuleInformation + sizeof(SIZE_T));

					snprintf(szIBase, PVOID_HEX_SIZE, "%P", pModuleInfo[0].Base);
					snprintf(szISize, PVOID_HEX_SIZE, "%P", pModuleInfo[0].Size);

					// Если есть путь к главному модулю, то выводим его
					if (pModuleInfo[0].ImageName)
					{
						li[0].pszText = pModuleInfo[0].ImageName;
					}

					// Получаем главную иконку процесса
					memset((LPVOID) & FileInfo, 0, sizeof(FileInfo));
					SHGetFileInfo(pModuleInfo[0].ImageName, 0, &FileInfo, sizeof(FileInfo), SHGFI_SMALLICON | SHGFI_ICON);
					//HANDLE sysil = (LPVOID)SHGetFileInfoA(pModuleInfo[0].ImageName, 0, &FileInfo, sizeof(FileInfo), SHGFI_SMALLICON | SHGFI_ICON | SHGFI_SYSICONINDEX );

					// Если иконку получить не удалось, загружаем иконку ошибки
					HICON hIcon = FileInfo.hIcon;	//ExtractIcon(ghInst, pModuleInfo[0].ImageName, 0);
					if (!hIcon)
						hIcon = LoadIcon(NULL, IDI_ERROR);
					CListView_AddToImageList(lvProcesses, hIcon);
					DestroyIcon(hIcon);
				}
				else
				{
					CListView_AddToImageList(lvProcesses, LoadIcon(NULL, IDI_ERROR));
				}

				//strlwr(li[0].pszText);

				CListView_AppendLine(lvProcesses, (LVITEM*)&li);

				if (!ret)
					RtlDestroyQueryDebugBuffer(pRtlBuffer);

			}
			*/

			VirtualFree(lpName, 0, MEM_RELEASE);

			nCount++;
			lpProcInfo = (PSYSTEM_PROCESSES) ((ULONG_PTR)lpProcInfo + lpProcInfo->NextEntryDelta);
		}
	}

	VirtualFree(lpProcInfoMem, 0, MEM_RELEASE);

	CListView_ApplyImageList(lvProcesses);

	for (size_t i = 1; i < 4; i++)
		ListView_SetColumnWidth(lvProcesses->hWnd, i, LVSCW_AUTOSIZE);
}

void ListModules_Insert(SIZE_T nIndex, LPSTR lpModName, LPVOID lpBase, SIZE_T dwImageSize)
{
	CHAR szIBase[PVOID_HEX_SIZE], szISize[PVOID_HEX_SIZE];
	LVITEM li[] = {
		{LVIF_TEXT, nIndex, 0, 0, 0, lpModName, 0, 0, 0, 0},
		{LVIF_TEXT, nIndex, 1, 0, 0, szIBase, 0, 0, 0, 0},
		{LVIF_TEXT, nIndex, 2, 0, 0, szISize, 0, 0, 0, 0},
	};
	snprintf(szIBase, PVOID_HEX_SIZE, "%P", lpBase);
	snprintf(szISize, PVOID_HEX_SIZE, "%P", dwImageSize);

	CListView_AppendLine(lvModules, (LVITEM*)&li);
}

void EnumModules(ULONG dwProcId)
{
	//SHFILEINFO FileInfo;
	size_t nCount = 0;

	ULONG uSysInfoSize = 0;

	uSelectedPid = dwProcId;

	CListView_Clear(lvModules);

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, dwProcId);
	if (hProcess == NULL)
		return;

#ifdef _WIN32
	BOOL bWow64 = FALSE;
	IsWow64Process(hProcess, &bWow64);
	if (!bWow64 && g_SysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64){
		CloseHandle(hProcess);
		return;
	}
#endif

	// Получаем информацию о процессе
	PROCESS_BASIC_INFORMATION BasicInfo = {0};
	ULONG ret = ZwQueryInformationProcess(hProcess, ProcessBasicInformation, &BasicInfo, sizeof(BasicInfo), NULL);
	if (ret == STATUS_INFO_LENGTH_MISMATCH)
	{
		MessageBoxA(0,"","",0);
		CloseHandle(hProcess);
		return;
	}

	PPEB lpPeb = BasicInfo.PebBaseAddress;
	struct _PEB_LDR_DATA *lpLdrPtr = NULL;
	SIZE_T dwRead = 0;
	ReadProcessMemory(hProcess, (LPVOID)((DWORD)lpPeb + offsetof(PEB, Ldr)), &lpLdrPtr, sizeof(lpLdrPtr), &dwRead);

	struct _PEB_LDR_DATA Ldr;
	ReadProcessMemory(hProcess, lpLdrPtr, &Ldr, sizeof(Ldr), &dwRead);

	LPVOID lpFirst = (LPVOID)Ldr.InLoadOrderModuleList.Flink;
	LPVOID lpCurEntry = lpFirst;
	while (1)
	{
		LDR_MODULE module = {0};
		ReadProcessMemory(hProcess, lpCurEntry, &module, sizeof(module), &dwRead);
		if (!module.BaseAddress || !module.SizeOfImage)
			break;

		CHAR *lpNameA  = malloc(module.FullDllName.MaximumLength+1);
		WCHAR *lpNameW = malloc(module.FullDllName.MaximumLength+1);
		if (lpNameA && lpNameW) {
			ReadProcessMemory(hProcess, module.FullDllName.Buffer, lpNameW, module.FullDllName.MaximumLength, &dwRead);
			wcstombs(lpNameA, lpNameW, module.FullDllName.MaximumLength);
			ListModules_Insert(nCount, lpNameA, (LPVOID)module.BaseAddress, module.SizeOfImage);
		}
		free(lpNameA);
		free(lpNameW);

		nCount++;
		lpCurEntry = module.InLoadOrderModuleList.Flink;
		if (lpCurEntry == lpFirst)
			break;
	}

	CloseHandle(hProcess);

	// Выравниваем размер колонок
	ListView_SetColumnWidth(lvModules->hWnd, 1, LVSCW_AUTOSIZE);
	ListView_SetColumnWidth(lvModules->hWnd, 2, LVSCW_AUTOSIZE);

	RECT rc;
	GetWindowRect(lvModules->hWnd, &rc);
	rc.right -= GetSystemMetrics(SM_CXVSCROLL) + 1;
	ListView_SetColumnWidth(lvModules->hWnd, 0, rc.right - rc.left - ListView_GetColumnWidth(lvModules->hWnd, 1) - ListView_GetColumnWidth(lvModules->hWnd, 2));


/*
	// Пытаемся получить список модулей процесса
	PDEBUG_BUFFER pRtlBuffer = RtlCreateQueryDebugBuffer(0, FALSE);
	if (pRtlBuffer)
	{
		ULONG ret = RtlQueryProcessDebugInformation(dwProcId, PDI_MODULES, pRtlBuffer);

		if (!ret && pRtlBuffer->ModuleInformation)
		{
			nCount = *(SIZE_T *)(pRtlBuffer->ModuleInformation);
			PDEBUG_MODULE_INFORMATION pModuleInfo = (PDEBUG_MODULE_INFORMATION) ((ULONG_PTR)pRtlBuffer->ModuleInformation + sizeof(SIZE_T));

			for (SIZE_T i = 0; i < nCount; i++)
			{
				ListModules_Insert(i, pModuleInfo[i].ImageName, (LPVOID)pModuleInfo[i].Base, pModuleInfo[i].Size);
			}

			// Выравниваем размер колонок
			ListView_SetColumnWidth(lvModules->hWnd, 1, LVSCW_AUTOSIZE);
			ListView_SetColumnWidth(lvModules->hWnd, 2, LVSCW_AUTOSIZE);

			RECT rc;
			GetWindowRect(lvModules->hWnd, &rc);
			rc.right -= GetSystemMetrics(SM_CXVSCROLL) + 1;
			ListView_SetColumnWidth(lvModules->hWnd, 0, rc.right - rc.left - ListView_GetColumnWidth(lvModules->hWnd, 1) - ListView_GetColumnWidth(lvModules->hWnd, 2));

			RtlDestroyQueryDebugBuffer(pRtlBuffer);
		}

	}
*/
}

void MainWndOnCreate(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	UINT columnMask = LVCF_TEXT | LVCF_FMT | LVCF_SUBITEM | LVCF_WIDTH;
	LVCOLUMN lc[] = {
		{columnMask, 0, 400, "Path",  0, 0, 0, 0},
		{columnMask, 0, 110, "PID",   0, 1, 0, 0},
		{columnMask, 0, 110, "IBase", 0, 2, 0, 0},
		{columnMask, 0, 110, "ISize", 0, 3, 0, 0},
	};

	/*ghWndProcList = CreateWindowEx(0, gszWndProcClass, NULL, 
		LVS_REPORT | WS_CHILD | WS_BORDER | LVS_SINGLESEL | LVS_NOSORTHEADER, 
		0, 0, 0, 0, 
		hWnd, NULL, ghInst, NULL);
	*/
	lvProcesses = CListView_Create(ghInst, gszWndProcClass, hWnd);
	//ghWndProcList = lvProcesses->hWnd;

	///ImageList_SetBkColor(himl, ListView_GetBkColor(ghWndProcList));

	CListView_InsertColumns(lvProcesses, lc, 4);

	// Заполняем список процессов
	EnumProcess();

	ShowWindow(lvProcesses->hWnd, SW_SHOW);

	lvModules = CListView_Create(ghInst, gszWndModulesClass, hWnd);
	//ghWndModuleList = lvModules->hWnd;
	/*ghWndModuleList = CreateWindowEx(0, gszWndModulesClass, NULL, 
		LVS_REPORT | WS_CHILD | WS_BORDER | LVS_SINGLESEL | LVS_NOSORTHEADER, 
		0, 0, 0, 0, 
		hWnd, NULL, ghInst, NULL);*/

	LVCOLUMN lcM[] = {
		{columnMask, 0, 400, "Path",  0, 0, 0, 0},
		{columnMask, 0, 110, "IBase", 0, 1, 0, 0},
		{columnMask, 0, 110, "ISize", 0, 2, 0, 0},
	};

	CListView_InsertColumns(lvModules, lcM, 3);

	ListView_SetColumnWidth(lvModules->hWnd, 1, ListView_GetColumnWidth(lvProcesses->hWnd, 2));
	ListView_SetColumnWidth(lvModules->hWnd, 2, ListView_GetColumnWidth(lvProcesses->hWnd, 3));

	//SendMessage(ghWndModuleList, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, /*LVS_EX_SIMPLESELECT |  LVS_EX_FLATSB | */ LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

	ShowWindow(lvModules->hWnd, SW_SHOW);

	SetFocus(lvProcesses->hWnd);
	//ListView_SetItemState(ghWndProcList, 20, LVIS_FOCUSED|LVIS_SELECTED, LVIS_FOCUSED|LVIS_SELECTED);
	//SendMessage(ghWndModuleList, LVM_ENSUREVISIBLE, 20, 0);
	//SendMessage(ListView_EditLabel(ghWndProcList, 20), WM_KEYDOWN, VK_DOWN, 0);
	//UpdateWindow(ghWndProcList);
}

void MainWndNmRClick(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	POINT p;
	GetCursorPos(&p);
	LPNMHDR hdr = (LPNMHDR)lParam;
	LPNMITEMACTIVATE lpnmitem = (LPNMITEMACTIVATE)lParam;
	// ..на списке процессов
	if (hdr->hwndFrom == lvProcesses->hWnd)
	{
		// Проверяем выделенный пункт
		SIZE_T nCount = lvProcesses->nElemsCount;//ListView_GetItemCount(ghWndProcList);
		if ((nCount == 0) || (lpnmitem->iItem > nCount))
			return;
		// Получаем из спика ProcId выделенного пункта
		CHAR tmp[MAX_PATH];
		ListView_GetItemText(lvProcesses->hWnd, lpnmitem->iItem, 1, tmp, MAX_PATH);
		ULONG_PTR uTmpVal = 0;
		sscanf(tmp, "%u", &uTmpVal);
		EnumModules(uTmpVal);

		/*HMENU hPopupMenu = CreatePopupMenu();
		InsertMenu(hPopupMenu, 0, MF_BYPOSITION | MF_STRING, ID_POPUP_P_DUMPFULL, "Dump Full...");
		InsertMenu(hPopupMenu, 1, MF_BYPOSITION | MF_STRING, ID_POPUP_P_DUMPPART, "Dump Partial...");
		InsertMenu(hPopupMenu, 2, MF_BYPOSITION | MF_STRING, ID_POPUP_P_DUMPREG, "Dump Region...");
		InsertMenu(hPopupMenu, 3, MF_SEPARATOR, 0, NULL);
		InsertMenu(hPopupMenu, 4, MF_BYPOSITION | MF_STRING, ID_POPUP_P_REFRESH, "Refresh [F5]");
		SetForegroundWindow(hdr->hwndFrom);
		TrackPopupMenu(hPopupMenu, TPM_TOPALIGN | TPM_LEFTALIGN, p.x, p.y, 0, hdr->hwndFrom, NULL);
		*/

		HMENU hPopupMenu = LoadMenu(ghInst, MAKEINTRESOURCE(2001));
		HMENU hSubMenu = GetSubMenu(hPopupMenu, 0);
		SetForegroundWindow(hdr->hwndFrom);
		TrackPopupMenu(hSubMenu, TPM_TOPALIGN | TPM_LEFTALIGN, p.x, p.y, 0, hdr->hwndFrom, NULL);
		DestroyMenu(hSubMenu);
		DestroyMenu(hPopupMenu);
	}
	// ...на списке модулей
	if (hdr->hwndFrom == lvModules->hWnd)
	{
		// Проверяем выделенный пункт
		SIZE_T nCount = lvModules->nElemsCount; //ListView_GetItemCount(ghWndModuleList);
		if ((nCount == 0) || (lpnmitem->iItem > nCount))
			return;

		/*HMENU hPopupMenu = CreatePopupMenu();
		InsertMenu(hPopupMenu, 0, MF_BYPOSITION | MF_STRING, ID_POPUP_M_DUMPFULL, "Dump Full...");
		InsertMenu(hPopupMenu, 1, MF_BYPOSITION | MF_STRING, ID_POPUP_M_DUMPPART, "Dump Partial...");
		InsertMenu(hPopupMenu, 2, MF_SEPARATOR, 0, NULL);
		InsertMenu(hPopupMenu, 3, MF_BYPOSITION | MF_STRING, ID_POPUP_M_REFRESH, "Refresh [F5]");
		SetForegroundWindow(hdr->hwndFrom);
		TrackPopupMenu(hPopupMenu, TPM_TOPALIGN | TPM_LEFTALIGN, p.x, p.y, 0, hdr->hwndFrom, NULL);*/
		HMENU hPopupMenu = LoadMenu(ghInst, MAKEINTRESOURCE(2002));
		HMENU hSubMenu = GetSubMenu(hPopupMenu, 0);
		SetForegroundWindow(hdr->hwndFrom);
		TrackPopupMenu(hSubMenu, TPM_TOPALIGN | TPM_LEFTALIGN, p.x, p.y, 0, hdr->hwndFrom, NULL);
		DestroyMenu(hSubMenu);
		DestroyMenu(hPopupMenu);
	}
}

LRESULT CALLBACK MainWndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message)
	{
		case WM_CREATE:
			MainWndOnCreate(hWnd, message, wParam, lParam);
			break;
		case WM_SIZE:
			{
				RECT rcMain;
				GetClientRect(hWnd, &rcMain);
				ListView_SetColumnWidth(lvProcesses->hWnd, 0, rcMain.right -
					ListView_GetColumnWidth(lvProcesses->hWnd, 1) -
					ListView_GetColumnWidth(lvProcesses->hWnd, 2) -
					ListView_GetColumnWidth(lvProcesses->hWnd, 3)-20);
				ListView_SetColumnWidth(lvModules->hWnd, 0, rcMain.right -
					ListView_GetColumnWidth(lvModules->hWnd, 1) -
					ListView_GetColumnWidth(lvModules->hWnd, 2) -20);
				MoveWindow(lvProcesses->hWnd, 0, 0, rcMain.right, rcMain.bottom >> 1, TRUE);
				MoveWindow(lvModules->hWnd, 0, (rcMain.bottom >> 1) + 5, rcMain.right, (rcMain.bottom >> 1) - 10, TRUE);

			}
			break;
		case WM_GETMINMAXINFO:
			{
				// Ограничиваем минимальный размер формы
				LPMINMAXINFO lpMMI = (LPMINMAXINFO)lParam;
				lpMMI->ptMinTrackSize.x = MAINWND_MIN_WIDTH;
				lpMMI->ptMinTrackSize.y = MAINWND_MIN_HEIGHT;
			}
			break;
		case WM_NOTIFY:
			{
				LPNMHDR hdr = (LPNMHDR)lParam;
				switch (hdr->code)
				{
					/*case LVN_COLUMNCLICK: {
						NMLISTVIEW* pListView = (NMLISTVIEW*)lParam;
						BOOL test = ListView_SortItems ( hdr->hwndFrom, ListViewCompareProc, pListView->iSubItem );
					}
						break;*/
					case NM_RCLICK:
						MainWndNmRClick(hWnd, message, wParam, lParam);
						break;

					case NM_CLICK:
						if (hdr->hwndFrom == lvProcesses->hWnd)
						{
							LPNMITEMACTIVATE lpnmitem = (LPNMITEMACTIVATE) lParam;
							SIZE_T nCount = ListView_GetItemCount(lvProcesses->hWnd);
							if ((nCount == 0) || (lpnmitem->iItem > nCount))
								break;
							// Получаем из спика ProcId выделенного пункта
							CHAR tmp[MAX_PATH];
							ListView_GetItemText(lvProcesses->hWnd, lpnmitem->iItem, 1, tmp, MAX_PATH);
							ULONG_PTR uTmpVal = 0;
							sscanf(tmp, "%u", &uTmpVal);
							EnumModules(uTmpVal);
						}
					break;

					// Делаем списки полосатыми
					case NM_CUSTOMDRAW:
						{
							LPNMLVCUSTOMDRAW lpCustom = (LPNMLVCUSTOMDRAW)lParam;
							switch (lpCustom->nmcd.dwDrawStage)
							{
								case CDDS_PREPAINT:
									return CDRF_NOTIFYITEMDRAW;
								case CDDS_ITEMPREPAINT:
									if (lpCustom->nmcd.dwItemSpec & 1)
									{
										//lpCustom->clrTextBk = 0x00FFFDE6;
										lpCustom->clrTextBk = ColorGrid;
									}
									return CDRF_NEWFONT;
							}
						}
						break;
				}
			}
			break;
		case WM_DESTROY:
			PostQuitMessage(0);
			break;
		default:
			return DefWindowProc(hWnd, message, wParam, lParam);
	}
	return 0;
}

BOOL DumpMemory(PDUMPPART_INIT lpDmpData, HWND hWndParent)
{
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, lpDmpData->dwProcId);
	if ((hProcess == NULL) || (hProcess == INVALID_HANDLE_VALUE))
	{
		MessageBox(hWndParent, "This process can't be dumped!", gszTitle, MB_ICONERROR | MB_OK);
		return FALSE;
	}
	MEMORY_BASIC_INFORMATION lpMemInfo = {0};
	VirtualQueryEx(hProcess, (LPCVOID)lpDmpData->Address, &lpMemInfo, sizeof(lpMemInfo));
	if (!(lpMemInfo.State & MEM_COMMIT))
	{
		MessageBox(hWndParent, "Can't dump non commit memory!", gszTitle, MB_ICONERROR | MB_OK);
		CloseHandle(hProcess);
		return FALSE;
	}

	WCHAR szInitDir[MAX_PATH] = {0};
	//GetModuleFileNameExW(hProcess, 0, szInitDir, MAX_PATH);
	MultiByteToWideChar(CP_ACP, 0, szSelectedModule, strlen(szSelectedModule), szInitDir, MAX_PATH);
	PathRemoveFileSpecW(szInitDir);
	//MessageBoxW(0, szInitDir, L"", 0);

	WCHAR szFile[MAX_PATH] = { 0 };
	if ((lpDmpData->Type == PARTIAL_TYPE) || (lpDmpData->Type == REGION_TYPE))
		wsprintfW(szFile, L"Dump%p_%p.dmp", lpDmpData->Address, lpDmpData->Size);

	OPENFILENAMEW ofn = { 0 };
	//ZeroMemory(&ofn, sizeof(ofn));
	ofn.lStructSize     = sizeof(ofn);
	ofn.hwndOwner       = ghWndMain;
	ofn.lpstrFile       = szFile;
	ofn.nMaxFile        = sizeof(szFile);
	ofn.lpstrFilter     = L"All files\0*.*\0";
	ofn.nFilterIndex    = 1;
	ofn.lpstrFileTitle  = NULL;
	ofn.nMaxFileTitle   = 0;
	ofn.lpstrInitialDir = szInitDir;
	ofn.lpstrDefExt     = L".dmp";
	ofn.Flags = OFN_PATHMUSTEXIST | OFN_CREATEPROMPT | OFN_OVERWRITEPROMPT;
	if (!GetSaveFileNameW(&ofn))
	{
		CloseHandle(hProcess);
		return FALSE;
	}
	HANDLE hFile = CreateFileW(szFile, GENERIC_WRITE, FILE_SHARE_READ, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL ,NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		MessageBox(hWndParent, "Unable create dump file!", gszTitle, MB_ICONERROR | MB_OK);
		CloseHandle(hProcess);
		return FALSE;
	}
	ULONG_PTR nMemSize = lpDmpData->Size;
	ULONG_PTR nMemPtr  = lpDmpData->Address;
	SIZE_T nNumRead;

	LPVOID lpMemBuf = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	BOOL bIsGood = TRUE;

	while (nMemSize > 0)
	{
		memset(lpMemBuf, 0, 4096);
		if (!(ReadProcessMemory(hProcess, (LPCVOID)nMemPtr, lpMemBuf, 4096, &nNumRead)) || (nNumRead == 0))
		{
			bIsGood = FALSE;
			break;
		}
		WriteFile(hFile, lpMemBuf, 4096, (PULONG)&nNumRead, NULL);
		nMemSize -= 4096;
		nMemPtr  += 4096;
	}

	VirtualFree(lpMemBuf, 0, MEM_RELEASE);

	CloseHandle(hFile);
	CloseHandle(hProcess);

	if (!bIsGood)
	{
		MessageBox(hWndParent, "Read memory fail!", gszTitle, MB_ICONERROR | MB_OK);
		return FALSE;
	}
	MessageBox(hWndParent, "Dump done!", gszTitle, MB_ICONINFORMATION | MB_OK);
	return TRUE;
} // DumpMemory


LRESULT CALLBACK ListProcessWndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message)
	{
		case WM_KEYDOWN:
			switch (wParam)
			{
				case VK_F5:
					{
						EnumProcess();
					}
					break;
			}
			break;
		case WM_COMMAND:
			{
				CHAR szTmp[MAX_PATH];
				ULONG_PTR uTmp, nLenBase, nLenSize, dwPid;
				dmpData.Type = PROCESS_TYPE;

				ListView_GetItemText(hWnd, ListView_GetSelectionMark(hWnd), 0, szSelectedModule, MAX_PATH);

				// Получаем PID процесса
				ListView_GetItemText(hWnd, ListView_GetSelectionMark(hWnd), 1, szTmp, MAX_PATH);
				sscanf(szTmp, "%lu", &dwPid);
				dmpData.dwProcId = dwPid;
					
				// Получаем IBase процесса
				ListView_GetItemText(hWnd, ListView_GetSelectionMark(hWnd), 2, szTmp, MAX_PATH);
				nLenBase = strlen(szTmp);
				sscanf(szTmp, "%0p", &uTmp);
				dmpData.Address = uTmp;

				// Получаем ISize процесса
				ListView_GetItemText(hWnd, ListView_GetSelectionMark(hWnd), 3, szTmp, MAX_PATH);
				nLenSize = strlen(szTmp);
				sscanf(szTmp, "%0p", &uTmp);
				dmpData.Size = uTmp;

				switch(LOWORD(wParam))
				{
					case ID_POPUP_P_DUMPFULL:
						{
							if (!nLenBase || !nLenSize) {
								MessageBox(ghWndMain, "This process can't be dumped!", gszTitle, MB_ICONERROR | MB_OK);
								break;
							}
							dmpData.Type = PROCESS_TYPE;
							DumpMemory(&dmpData, ghWndMain);
						}
						break;
					case ID_POPUP_P_DUMPPART:
						{
							HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, dwPid);
							if ((!hProcess) || (hProcess == INVALID_HANDLE_VALUE) || (!nLenBase) || (!nLenSize))
							{
								MessageBox(ghWndMain, "This process can't be dumped!", gszTitle, MB_ICONERROR | MB_OK);
								break;
							}
							CloseHandle(hProcess);
							DialogBoxParam(ghInst, DLG_PARTIAL_ID, ghWndMain, DumpPartDialogProc, 0);
						}
						break;
					case ID_POPUP_P_DUMPREG:
						{
							HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, dwPid);
							if ((!hProcess) || (hProcess == INVALID_HANDLE_VALUE) || (!nLenBase) || (!nLenSize))
							{
								MessageBox(ghWndMain, "This process can't be dumped!", gszTitle, MB_ICONERROR | MB_OK);
								break;
							}
							CloseHandle(hProcess);
							DialogBoxParam(ghInst, DLG_REGION_ID, ghWndMain, DumpRegionDialogProc, 0);
						}
						break;
					case ID_POPUP_P_REFRESH:
						EnumProcess();
						break;
				}
			}
			break;
		default:
			return CallWindowProc((WNDPROC)origWndProcProcess, hWnd, message, wParam, lParam);
	}
	return 0;
} // ListProcessWndProc

LRESULT CALLBACK ListModulesWndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message)
	{
		case WM_KEYDOWN:
			switch (wParam)
			{
				case VK_F5:
					{
						EnumModules(uSelectedPid);
					}
					break;
			}
			break;
		case WM_COMMAND:
			{
				CHAR szTmp[MAX_PATH];
				ULONG_PTR uTmp, nLenBase, nLenSize;
				dmpData.Type = MODULE_TYPE;
				dmpData.dwProcId = uSelectedPid;

				ListView_GetItemText(hWnd, ListView_GetSelectionMark(hWnd), 0, szSelectedModule, MAX_PATH);
					
				// Получаем IBase процесса
				ListView_GetItemText(hWnd, ListView_GetSelectionMark(hWnd), 1, szTmp, MAX_PATH);
				nLenBase = strlen(szTmp);
				sscanf(szTmp, "%0p", &uTmp);
				dmpData.Address = uTmp;

				// Получаем ISize процесса
				ListView_GetItemText(hWnd, ListView_GetSelectionMark(hWnd), 2, szTmp, MAX_PATH);
				nLenSize = strlen(szTmp);
				sscanf(szTmp, "%0p", &uTmp);
				dmpData.Size = uTmp;


				switch(LOWORD(wParam))
				{
					case ID_POPUP_M_DUMPFULL:
						{
							HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, uSelectedPid);
							if ((!hProcess) || (hProcess == INVALID_HANDLE_VALUE) || (!nLenBase) || (!nLenSize))
							{
								MessageBox(ghWndMain, "This process can't be dumped!", gszTitle, MB_ICONERROR | MB_OK);
								break;
							}
							CloseHandle(hProcess);
							dmpData.Type = MODULE_TYPE;
							DumpMemory(&dmpData, ghWndMain);
						}
						break;
					case ID_POPUP_M_DUMPPART:
						{
							HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, uSelectedPid);
							if ((!hProcess) || (hProcess == INVALID_HANDLE_VALUE) || (!nLenBase) || (!nLenSize))
							{
								MessageBox(ghWndMain, "This process can't be dumped!", gszTitle, MB_ICONERROR | MB_OK);
								break;
							}
							DialogBoxParam(ghInst, DLG_PARTIAL_ID, ghWndMain, DumpPartDialogProc, 0);
						}
						break;
					case ID_POPUP_M_REFRESH:
						EnumModules(uSelectedPid);
						break;
				}
			}
			break;
		default:
			return CallWindowProc((WNDPROC)origWndProcModules, hWnd, message, wParam, lParam);
	}
	return 0;
}

ATOM MainWndRegisterClass(HINSTANCE hInstance)
{
	WNDCLASSEX wcex;

	memset(&wcex, 0, sizeof(WNDCLASSEX));

	wcex.cbSize = sizeof(WNDCLASSEX);
	//wcex.style = CS_HREDRAW | CS_VREDRAW;
	wcex.lpfnWndProc = (WNDPROC)MainWndProc;
	wcex.hInstance = hInstance;
	wcex.hCursor = LoadCursor(NULL, IDC_ARROW);
	wcex.hbrBackground = (HBRUSH) (COLOR_WINDOW);
	//wcex.lpszMenuName = "#2001";  //(LPCTSTR)IDR_MAINMENU;
	wcex.lpszClassName = (LPCTSTR)gszWndMainClass;

	return RegisterClassEx(&wcex);
}

ATOM ChildWndRegisterClass(HINSTANCE hInstance)
{
	ATOM Result = 0;
	WNDCLASSEX wcex;

	GetClassInfoEx(hInstance, "SysListView32", &wcex);

	origWndProcProcess = wcex.lpfnWndProc;
	wcex.lpfnWndProc = &ListProcessWndProc;
	wcex.cbSize = sizeof(WNDCLASSEX);
	wcex.lpszClassName = (LPCTSTR)gszWndProcClass;
	wcex.hInstance = hInstance;

	Result = RegisterClassEx(&wcex);

	GetClassInfoEx(hInstance, "SysListView32", &wcex);

	origWndProcModules = wcex.lpfnWndProc;
	wcex.lpfnWndProc = &ListModulesWndProc;
	wcex.cbSize = sizeof(WNDCLASSEX);
	wcex.lpszClassName = (LPCTSTR)gszWndModulesClass;
	wcex.hInstance = hInstance;

	Result |= RegisterClassEx(&wcex);


	return Result;
}

BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
	ghInst = hInstance;

	ghWndMain = CreateWindow(gszWndMainClass, gszTitle, WS_OVERLAPPEDWINDOW  | WS_CLIPCHILDREN | WS_VISIBLE , CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, NULL, NULL, hInstance, NULL);

	if (!ghWndMain)
		return FALSE;

	ShowWindow(ghWndMain, nCmdShow);
	UpdateWindow(ghWndMain);

	return TRUE;
}

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	MSG msg;

	InitCommonControls();
	CoInitialize(NULL);
	//SetThemeAppProperties(STAP_ALLOW_NONCLIENT | STAP_ALLOW_CONTROLS | STAP_ALLOW_WEBCONTENT);

	if (!AdjustPrivilege(SE_DEBUG_NAME, 1))
		MessageBox(0, "SeDebugPrivilege was not enabled!", gszTitle, MB_ICONERROR | MB_OK);

	HMODULE hNtdll = GetModuleHandle("ntdll");
	/*
	   ZwQuerySystemInformation = (pfnZwQuerySystemInformation)GetProcAddress(hNtdll, "ZwQuerySystemInformation");
	   RtlCreateQueryDebugBuffer = (pfnRtlCreateQueryDebugBuffer)GetProcAddress(hNtdll, "RtlCreateQueryDebugBuffer");
	   RtlQueryProcessDebugInformation = (pfnRtlQueryProcessDebugInformation)GetProcAddress(hNtdll, "RtlQueryProcessDebugInformation");
	   RtlDestroyQueryDebugBuffer = (pfnRtlDestroyQueryDebugBuffer)GetProcAddress(hNtdll, "RtlDestroyQueryDebugBuffer");
	 */
	GET_API(hNtdll, ZwQuerySystemInformation);
	GET_API(hNtdll, ZwQueryInformationProcess);
	GET_API(hNtdll, RtlCreateQueryDebugBuffer);
	GET_API(hNtdll, RtlQueryProcessDebugInformation);
	GET_API(hNtdll, RtlDestroyQueryDebugBuffer);

	GetNativeSystemInfo(&g_SysInfo);

	ColorGrid = GetSysColor(COLOR_WINDOW) - 0x080808;

	himl = ImageList_Create(GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), ILC_COLORDDB | ILC_MASK, 100, 1);

	if (!MainWndRegisterClass(hInstance) || !ChildWndRegisterClass(hInstance))
		return FALSE;

	if (!InitInstance(hInstance, nCmdShow))
		return FALSE;

	while (GetMessage(&msg, NULL, 0, 0))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}

	ImageList_Destroy(himl);

	return (int)msg.wParam;
}
