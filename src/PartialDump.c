#include "PartialDump.h"

void OnPartialDumpInitDialog(HWND hWnd)
{
	CHAR tmp[MAX_PATH];
	// Заполняем поля Address и Size настоящими значениями
	sprintf(tmp, "%P", dmpData.Address);
	SetWindowText(GetDlgItem(hWnd, ID_PART_EDIT_ADDRESS), tmp);

	sprintf(tmp, "%P", dmpData.Size);
	SetWindowText(GetDlgItem(hWnd, ID_PART_EDIT_SIZE), tmp);

	// Так же правим текст надписей
	sprintf(tmp, "Range [%P-%P]", dmpData.Address, dmpData.Address + dmpData.Size);
	SetWindowText(GetDlgItem(hWnd, ID_PART_LABEL_ADDRESS), tmp);

	sprintf(tmp, "Range [%P-%P]", 0, dmpData.Size);
	SetWindowText(GetDlgItem(hWnd, ID_PART_LABEL_SIZE), tmp);

	// Ограничиваем размер вводимых строк
	SendMessage(GetDlgItem(hWnd, ID_PART_EDIT_ADDRESS), EM_LIMITTEXT, sizeof(LPVOID) * 2, 0);
	SendMessage(GetDlgItem(hWnd, ID_PART_EDIT_SIZE), EM_LIMITTEXT, sizeof(LPVOID) * 2, 0);
}

void OnPartialDumpPressOkButton(HWND hWnd)
{
	CHAR szGetBuf[MAX_PATH];
	ULONG_PTR uGetVal = 0;

	// Получаем значение адреса
	GetWindowText(GetDlgItem(hWnd, ID_PART_EDIT_ADDRESS), szGetBuf, MAX_PATH);

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
		return;
	}
	sscanf(szGetBuf, "%p", &uGetVal);
	dmpData.Address = uGetVal;

	// Получаем значение размера
	GetWindowText(GetDlgItem(hWnd, ID_PART_EDIT_SIZE), szGetBuf, MAX_PATH);

	// Проверяем, что это hex значение
	nLen = strlen(szGetBuf);
	for (i = 0; i < nLen; i++)
	{
		if (!isxdigit(szGetBuf[i]))
			return;
	}
	if (i != nLen)
	{
		MessageBox(ghWndMain, "Incorrect Size value!", gszTitle, MB_ICONERROR | MB_OK);
		return;
	}
	sscanf(szGetBuf, "%0p", &uGetVal);
	dmpData.Size = uGetVal;
	dmpData.dwProcId = uSelectedPid;
	dmpData.Type = PARTIAL_TYPE;

	// Дампим область
	if (DumpMemory(&dmpData, hWnd))
		EndDialog(hWnd, 0);
}

BOOL CALLBACK DumpPartDialogProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message)
	{
		case WM_INITDIALOG:
			{
				OnPartialDumpInitDialog(hWnd);
			}
			break;
		case WM_COMMAND:
			switch (LOWORD(wParam))
			{
				case IDCANCEL:
					EndDialog(hWnd, 0);
					break;
				case IDOK:
				{
					OnPartialDumpPressOkButton(hWnd);
				}
				break;
			}
			break;
		case WM_CLOSE:
			EndDialog(hWnd, 0);
			break;
	}
	return FALSE;
}
