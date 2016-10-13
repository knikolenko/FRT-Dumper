#include "RegionDump.h"

void GetMemoryInfo(SIZE_T dwProcessId, HWND hWndList)
{
	ULONG_PTR lpCurAddr = 0, lpPrevAddr = 0;;
	MEMORY_BASIC_INFORMATION lpMemInfo = {0};
	CHAR szBaseAddress[sizeof(LPVOID) * 2 + 1], szRegionSize[sizeof(LPVOID) * 2 + 1], szProtect[MAX_PATH];
	CHAR *pszProtect, *pszState, *pszType;

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, dwProcessId);
	if ((hProcess == NULL) || (hProcess == INVALID_HANDLE_VALUE))
	{
		MessageBox(ghWndMain, "Get memory info fail!", gszTitle, MB_ICONERROR | MB_OK);
		return;
	}

	ListView_DeleteAllItems(hWndList);
	
	UINT itemMask = LVIF_TEXT;
	SIZE_T i = 0;
	while(VirtualQueryEx(hProcess, (LPCVOID)lpCurAddr, &lpMemInfo, sizeof(lpMemInfo)))
	{
		pszType = "NONE";
		if (lpMemInfo.Type & MEM_IMAGE)   pszType = "IMAGE";
		if (lpMemInfo.Type & MEM_MAPPED)  pszType = "MAPPED";
		if (lpMemInfo.Type & MEM_PRIVATE) pszType = "PRIVATE";

		pszProtect = "NONE";
		if (lpMemInfo.Protect & PAGE_NOACCESS) pszProtect = "NO ACCESS";
		if (lpMemInfo.Protect & PAGE_READONLY) pszProtect = "READ ONLY";
		if (lpMemInfo.Protect & PAGE_READWRITE) pszProtect = "READ/WRITE";
		if (lpMemInfo.Protect & PAGE_WRITECOPY) pszProtect = "WRITE/COPY";
		if (lpMemInfo.Protect & PAGE_EXECUTE_WRITECOPY) pszProtect = "EXECUTE WRITE/COPY";
		if (lpMemInfo.Protect & PAGE_EXECUTE_READWRITE) pszProtect = "EXECUTE READ/WRITE";
		if (lpMemInfo.Protect & PAGE_EXECUTE_READ) pszProtect = "EXECUTE READ";
		if (lpMemInfo.Protect & PAGE_EXECUTE) pszProtect = "EXECUTE";

		strcpy(szProtect, pszProtect);
		if (lpMemInfo.Protect & PAGE_GUARD)
			strcat(szProtect, " | PAGE GUARD");

		pszState = "UNKNOW";
		if (lpMemInfo.State & MEM_COMMIT)  pszState = "COMMIT";
		if (lpMemInfo.State & MEM_FREE)    pszState = "FREE";
		if (lpMemInfo.State & MEM_RESERVE) pszState = "RESERVE";

		LVITEM li[] = {
			{itemMask, i, 0, 0, 0, szBaseAddress, 0, 0, 0, 0},
			{itemMask, i, 1, 0, 0, szRegionSize, 0, 0, 0, 0},
			{itemMask, i, 2, 0, 0, szProtect, 0, 0, 0, 0},
			{itemMask, i, 3, 0, 0, pszState, 0, 0, 0, 0},
			{itemMask, i, 4, 0, 0, pszType, 0, 0, 0, 0},
		};

		snprintf(szBaseAddress, sizeof(LPVOID) * 2 + 1, "%P", lpMemInfo.BaseAddress);
		snprintf(szRegionSize,  sizeof(LPVOID) * 2 + 1, "%P", lpMemInfo.RegionSize);

		//MessageBox(0, szBaseAddress, szRegionSize, 0);

		ListView_InsertItem(hWndList, &li[0]);
		ListView_SetItem(hWndList, &li[1]);
		ListView_SetItem(hWndList, &li[2]);
		ListView_SetItem(hWndList, &li[3]);
		ListView_SetItem(hWndList, &li[4]);

		lpPrevAddr = lpCurAddr;

		lpCurAddr = (ULONG_PTR)lpMemInfo.BaseAddress + lpMemInfo.RegionSize;
		if (lpCurAddr <= lpPrevAddr) break;
		i++;
	}
	CloseHandle(hProcess);
}

void OnRegionDumpInitDialog(HWND hWnd)
{
	CHAR tmp[MAX_PATH];
	HWND hWndList = GetDlgItem(hWnd, ID_REGION_LIST);

	// Создаем колонки списка
	UINT columnMask = LVCF_TEXT | LVCF_FMT | LVCF_SUBITEM | LVCF_WIDTH;
	LVCOLUMN lc[] = {
		{columnMask, 0, 110, "Address", 0, 0, 0, 0}
		,
		{columnMask, 0, 110, "Size", 0, 1, 0, 0}
		,
		{columnMask, 0, 110, "Protect", 0, 2, 0, 0}
		,
		{columnMask, 0, 110, "State", 0, 3, 0, 0}
		,
		{columnMask, 0, 110, "Type", 0, 4, 0, 0}
		,
	};

	ListView_InsertColumn(hWndList, 0, &lc[0]);
	ListView_InsertColumn(hWndList, 1, &lc[1]);
	ListView_InsertColumn(hWndList, 2, &lc[2]);
	ListView_InsertColumn(hWndList, 3, &lc[3]);
	ListView_InsertColumn(hWndList, 4, &lc[4]);

	SendMessage(hWndList, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, /*LVS_EX_SIMPLESELECT |  LVS_EX_FLATSB | */ LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

	// Заполняем список
	GetMemoryInfo(uSelectedPid, hWndList);

	ListView_SetColumnWidth(hWndList, 0, LVSCW_AUTOSIZE);
	ListView_SetColumnWidth(hWndList, 1, LVSCW_AUTOSIZE);
	ListView_SetColumnWidth(hWndList, 2, LVSCW_AUTOSIZE);
	ListView_SetColumnWidth(hWndList, 3, LVSCW_AUTOSIZE);
	ListView_SetColumnWidth(hWndList, 4, LVSCW_AUTOSIZE);

	// Заполняем поля Address и Size настоящими значениями
	sprintf(tmp, "%P", dmpData.Address);
	SetWindowText(GetDlgItem(hWnd, ID_REGION_EDIT_ADDRESS), tmp);

	sprintf(tmp, "%P", dmpData.Size);
	SetWindowText(GetDlgItem(hWnd, ID_REGION_EDIT_SIZE), tmp);
}

BOOL CALLBACK DumpRegionDialogProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message)
	{
		case WM_INITDIALOG:
			{
				OnRegionDumpInitDialog(hWnd);
			}
			break;
		case WM_COMMAND:
			switch (LOWORD(wParam))
			{
				case IDCANCEL:
					EndDialog(hWnd, 0);
					break;
				case ID_REGION_BTN_REFRESH:
					{
						CHAR tmp[MAX_PATH];
						GetMemoryInfo(uSelectedPid, GetDlgItem(hWnd, ID_REGION_LIST));
						// Заполняем поля Address и Size настоящими значениями
						sprintf(tmp, "%P", dmpData.Address);
						SetWindowText(GetDlgItem(hWnd, ID_REGION_EDIT_ADDRESS), tmp);

						sprintf(tmp, "%P", dmpData.Size);
						SetWindowText(GetDlgItem(hWnd, ID_REGION_EDIT_SIZE), tmp);
					}
					break;
				case IDOK:
					{
						CHAR szGetBuf[MAX_PATH];
						ULONG_PTR uGetVal = 0;

						// Получаем значение адреса
						GetWindowText(GetDlgItem(hWnd, ID_REGION_EDIT_ADDRESS), szGetBuf, MAX_PATH);

						// Проверяем, что это hex значение
						SIZE_T i, nLen = strlen(szGetBuf);
						for (i = 0; i < nLen; i++)
						{
							if (!isxdigit(szGetBuf[i]))
								break;
						}
						if (i != nLen)
						{
							MessageBox(ghWndMain, "Incorrect Address value!", gszTitle, MB_ICONERROR | MB_OK);
							break;
						}
						sscanf(szGetBuf, "%0p", &uGetVal);
						dmpData.Address = uGetVal;

						// Получаем значение размера
						GetWindowText(GetDlgItem(hWnd, ID_REGION_EDIT_SIZE), szGetBuf, MAX_PATH);

						// Проверяем, что это hex значение
						nLen = strlen(szGetBuf);
						for (i = 0; i < nLen; i++)
						{
							if (!isxdigit(szGetBuf[i]))
								break;
						}
						if (i != nLen)
						{
							MessageBox(ghWndMain, "Incorrect Size value!", gszTitle, MB_ICONERROR | MB_OK);
							break;
						}
						sscanf(szGetBuf, "%0p", &uGetVal);
						dmpData.Size = uGetVal;
						dmpData.dwProcId = uSelectedPid;
						dmpData.Type = REGION_TYPE;

						// Дампим область
						if (DumpMemory(&dmpData, hWnd)) EndDialog(hWnd, 0);
					}
					break;

			}
			break;
		case WM_NOTIFY:
			{
				LPNMHDR hdr = (LPNMHDR)lParam;
				HWND hWndList = GetDlgItem(hWnd, ID_REGION_LIST);
				if ((hdr->code == NM_CLICK) && (hdr->hwndFrom == hWndList))
				{
					LPNMITEMACTIVATE lpnmitem = (LPNMITEMACTIVATE) lParam;
					ULONG nCount = ListView_GetItemCount(hWndList);
					if ((nCount == 0) || (lpnmitem->iItem > nCount))
						break;

					CHAR tmp[sizeof(LPVOID) * 2 + 1];
					// Копируем выделенный адрес
					ListView_GetItemText(hWndList, lpnmitem->iItem, 0, tmp, sizeof(LPVOID) * 2 + 1);
					SetWindowText(GetDlgItem(hWnd, ID_REGION_EDIT_ADDRESS), tmp);

					// Копируем размер
					ListView_GetItemText(hWndList, lpnmitem->iItem, 1, tmp, sizeof(LPVOID) * 2 + 1);
					SetWindowText(GetDlgItem(hWnd, ID_REGION_EDIT_SIZE), tmp);
				}
			}
			break;
		case WM_CLOSE:
			EndDialog(hWnd, 0);
			break;
	}
	return FALSE;
}
