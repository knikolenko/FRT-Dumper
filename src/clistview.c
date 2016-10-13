#include "clistview.h"

CListView* CListView_Create(HINSTANCE hInstance, LPTSTR lpClassName, HWND hWndParent)
{
	HWND hWndList = CreateWindowEx(0, lpClassName, NULL, 
		LVS_REPORT | WS_CHILD | WS_BORDER | LVS_SINGLESEL | LVS_NOSORTHEADER, 
		0, 0, 0, 0, 
		hWndParent, NULL, hInstance, NULL);

	if (!hWndList)
		return NULL;
	CListView* lv = malloc(sizeof(CListView));
	if (!lv)
		return NULL;
	lv->hWnd = hWndList;
	lv->hImageList = ImageList_Create(GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), ILC_COLORDDB | ILC_MASK, 1024, 1);
	ImageList_SetBkColor(lv->hImageList, ListView_GetBkColor(lv->hWnd));
	CListView_Clear(lv);
	SendMessage(lv->hWnd, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, /*LVS_EX_SIMPLESELECT |  LVS_EX_FLATSB  | */ LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_ONECLICKACTIVATE);
	return lv;
}

void CListView_Clear(CListView* lv)
{
	if (!lv || IsBadReadPtr(lv, sizeof(*lv)))
		return;

	ListView_DeleteAllItems(lv->hWnd);
	ImageList_RemoveAll(lv->hImageList);
	lv->nElemsCount = 0;
}

void CListView_InsertColumns(CListView* lv, LVCOLUMN *lpColumn, size_t nCount)
{
	if (!lv || !lpColumn || IsBadReadPtr(lv, sizeof(*lv)))
		return;
	lv->nColumnCount = nCount;
	for (size_t i = 0; i < nCount; i++)
		ListView_InsertColumn(lv->hWnd, i, &lpColumn[i]);
}

void CListView_AppendLine(CListView* lv, LVITEM *li)
{
	if (!lv || IsBadReadPtr(lv, sizeof(*lv)))
		return;

	if (lv->nColumnCount > 0)
		ListView_InsertItem(lv->hWnd, &li[0]);
	for (size_t i = 1; i < lv->nColumnCount; i++)
		ListView_SetItem(lv->hWnd, &li[i]);
	lv->nElemsCount++;
}

void CListView_ApplyImageList(CListView* lv)
{
	if (!lv || IsBadReadPtr(lv, sizeof(*lv)))
		return;
	ListView_SetImageList(lv->hWnd, lv->hImageList, LVSIL_SMALL);
}

void CListView_AddToImageList(CListView* lv, HICON hIcon)
{
	if (!lv || IsBadReadPtr(lv, sizeof(*lv)))
		return;
	ImageList_AddIcon(lv->hImageList, hIcon);
}
