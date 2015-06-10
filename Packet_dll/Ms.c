// Win10Pcap: WinPcap for Windows 10
// 
// Win10Pcap is free software under GPLv2.
// 
// Copyright (c) 2015 Daiyuu Nobori, University of Tsukuba, Japan.
// 
// All Rights Reserved.
// 
// http://www.win10pcap.org/
// 
// Author: Daiyuu Nobori
// 
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// version 2 as published by the Free Software Foundation.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License version 2
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
// TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
// SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
// 
// THIS SOFTWARE IS DEVELOPED IN JAPAN, AND DISTRIBUTED FROM JAPAN,
// UNDER JAPANESE LAWS. YOU MUST AGREE IN ADVANCE TO USE, COPY, MODIFY,
// MERGE, PUBLISH, DISTRIBUTE, SUBLICENSE, AND/OR SELL COPIES OF THIS
// SOFTWARE, THAT ANY JURIDICAL DISPUTES WHICH ARE CONCERNED TO THIS
// SOFTWARE OR ITS CONTENTS, AGAINST US (SOFTETHER PROJECT, SOFTETHER
// CORPORATION, DAIYUU NOBORI OR OTHER SUPPLIERS), OR ANY JURIDICAL
// DISPUTES AGAINST US WHICH ARE CAUSED BY ANY KIND OF USING, COPYING,
// MODIFYING, MERGING, PUBLISHING, DISTRIBUTING, SUBLICENSING, AND/OR
// SELLING COPIES OF THIS SOFTWARE SHALL BE REGARDED AS BE CONSTRUED AND
// CONTROLLED BY JAPANESE LAWS, AND YOU MUST FURTHER CONSENT TO
// EXCLUSIVE JURISDICTION AND VENUE IN THE COURTS SITTING IN TOKYO,
// JAPAN. YOU MUST WAIVE ALL DEFENSES OF LACK OF PERSONAL JURISDICTION
// AND FORUM NON CONVENIENS. PROCESS MAY BE SERVED ON EITHER PARTY IN
// THE MANNER AUTHORIZED BY APPLICABLE LAW OR COURT RULE.
// 
// USE ONLY IN JAPAN. DO NOT USE THIS SOFTWARE IN ANOTHER COUNTRY UNLESS
// YOU HAVE A CONFIRMATION THAT THIS SOFTWARE DOES NOT VIOLATE ANY
// CRIMINAL LAWS OR CIVIL RIGHTS IN THAT PARTICULAR COUNTRY. USING THIS
// SOFTWARE IN OTHER COUNTRIES IS COMPLETELY AT YOUR OWN RISK. THE
// SOFTETHER VPN PROJECT HAS DEVELOPED AND DISTRIBUTED THIS SOFTWARE TO
// COMPLY ONLY WITH THE JAPANESE LAWS AND EXISTING CIVIL RIGHTS INCLUDING
// PATENTS WHICH ARE SUBJECTS APPLY IN JAPAN. OTHER COUNTRIES' LAWS OR
// CIVIL RIGHTS ARE NONE OF OUR CONCERNS NOR RESPONSIBILITIES. WE HAVE
// NEVER INVESTIGATED ANY CRIMINAL REGULATIONS, CIVIL LAWS OR
// INTELLECTUAL PROPERTY RIGHTS INCLUDING PATENTS IN ANY OF OTHER 200+
// COUNTRIES AND TERRITORIES. BY NATURE, THERE ARE 200+ REGIONS IN THE
// WORLD, WITH DIFFERENT LAWS. IT IS IMPOSSIBLE TO VERIFY EVERY
// COUNTRIES' LAWS, REGULATIONS AND CIVIL RIGHTS TO MAKE THE SOFTWARE
// COMPLY WITH ALL COUNTRIES' LAWS BY THE PROJECT. EVEN IF YOU WILL BE
// SUED BY A PRIVATE ENTITY OR BE DAMAGED BY A PUBLIC SERVANT IN YOUR
// COUNTRY, THE DEVELOPERS OF THIS SOFTWARE WILL NEVER BE LIABLE TO
// RECOVER OR COMPENSATE SUCH DAMAGES, CRIMINAL OR CIVIL
// RESPONSIBILITIES. NOTE THAT THIS LINE IS NOT LICENSE RESTRICTION BUT
// JUST A STATEMENT FOR WARNING AND DISCLAIMER.

#define	_WIN32_WINNT		0x0502
#define	WINVER				0x0502
#define   SECURITY_WIN32
#include <winsock2.h>
#include <windows.h>
#include <Wintrust.h>
#include <Softpub.h>
#include <Iphlpapi.h>
#include <ws2ipdef.h>
#include <netioapi.h>
#include <tlhelp32.h>
#include <wincon.h>
#include <Nb30.h>
#include <shlobj.h>
#include <commctrl.h>
#include <Dbghelp.h>
#include <setupapi.h>
#include <regstr.h>
#include <process.h>
#include <psapi.h>
#include <wtsapi32.h>
#include <security.h>
#include <Msi.h>
#include <Msiquery.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include "Se.h"
#include "Packet32.h"
#include "NdisDriverUser.h"
#include "Packet32_Internal.h"
#include "Ms.h"

static LOCK *lock_adapter_list = NULL;
static MS_ADAPTER_LIST *last_adapter_list = NULL;

// Wait for the process termination
bool Win32WaitProcess(void *h, UINT timeout)
{
	// Validate arguments
	if (h == NULL)
	{
		return false;
	}
	if (timeout == 0)
	{
		timeout = INFINITE;
	}

	if (WaitForSingleObject((HANDLE)h, timeout) == WAIT_TIMEOUT)
	{
		return false;
	}

	return true;
}

void *Win32RunEx3(char *filename, char *arg, bool hide, UINT *process_id, bool disableWow)
{
	STARTUPINFO info;
	PROCESS_INFORMATION ret;
	char cmdline[MAX_SIZE];
	char name[MAX_PATH];
	void *p = NULL;
	// Validate arguments
	if (filename == NULL)
	{
		return NULL;
	}

	SeStrCpy(name, sizeof(name), filename);
	SeTrim(name);

	wsprintfA(cmdline, "\"%s\" %s", filename, arg);

	SeZero(&info, sizeof(info));
	SeZero(&ret, sizeof(ret));
	info.cb = sizeof(info);
	info.dwFlags = STARTF_USESHOWWINDOW;
	info.wShowWindow = (hide == false ? SW_SHOWDEFAULT : SW_HIDE);

	SeTrim(cmdline);

	if (disableWow)
	{
		p = DisableWow64FsRedirection();
	}

	if (CreateProcessA(NULL, cmdline, NULL, NULL, FALSE,
		(hide == false ? CREATE_NEW_CONSOLE : CREATE_NO_WINDOW | CREATE_NEW_CONSOLE) | NORMAL_PRIORITY_CLASS,
		NULL, NULL, &info, &ret) == FALSE)
	{
		if (disableWow)
		{
			RestoreWow64FsRedirection(p);
		}
		return NULL;
	}
	if (disableWow)
	{
		RestoreWow64FsRedirection(p);
	}

	if (process_id != NULL)
	{
		*process_id = ret.dwProcessId;
	}

	CloseHandle(ret.hThread);
	return ret.hProcess;
}

// Run the process and wait for terminate it
bool Win32RunAndWaitProcess(char *filename, char *arg, bool hide, bool disableWow, UINT timeout)
{
	UINT process_id = 0;
	void *p = Win32RunEx3(filename, arg, hide, &process_id, disableWow);

	if (p == NULL)
	{
		return false;
	}

	return Win32WaitProcess(p, timeout);
}

void *DisableWow64FsRedirection()
{
	void *p = NULL;

	if (IsWow64() == false)
	{
		return NULL;
	}

	if (Wow64DisableWow64FsRedirection(&p) == false)
	{
		return NULL;
	}

	return p;
}

void RestoreWow64FsRedirection(void *p)
{
	if (p == NULL)
	{
		return;
	}

	if (IsWow64() == false)
	{
		return;
	}

	Wow64RevertWow64FsRedirection(p);
}

BOOL MsGetFileVersion(LPTSTR FileName, PCHAR VersionBuff, UINT VersionBuffLen)
{
	DWORD   dwVerInfoSize;  // Size of version information block
	DWORD   dwVerHnd=0;   // An 'ignored' parameter, always '0'
	LPSTR   lpstrVffInfo;
	UINT	cbTranslate, dwBytes;
	TCHAR	SubBlock[64];
	PVOID	lpBuffer;
	PCHAR	TmpStr;

	// Structure used to store enumerated languages and code pages.
	struct LANGANDCODEPAGE {
		WORD wLanguage;
		WORD wCodePage;
	} *lpTranslate;

	// Now lets dive in and pull out the version information:
	dwVerInfoSize = GetFileVersionInfoSize(FileName, &dwVerHnd);
	if (dwVerInfoSize) 
	{
		lpstrVffInfo = SeMalloc(dwVerInfoSize);
		if (lpstrVffInfo == NULL)
		{
			return FALSE;
		}

		if(!GetFileVersionInfo(FileName, dwVerHnd, dwVerInfoSize, lpstrVffInfo)) 
		{
			SeFree(lpstrVffInfo);
			return FALSE;
		}

		// Read the list of languages and code pages.
		if(!VerQueryValue(lpstrVffInfo,	TEXT("\\VarFileInfo\\Translation"),	(LPVOID*)&lpTranslate, &cbTranslate))
		{
			SeFree(lpstrVffInfo);
			return FALSE;
		}

		// Create the file version string for the first (i.e. the only one) language.
		wsprintfA( SubBlock, 
			TEXT("\\StringFileInfo\\%04x%04x\\FileVersion"),
			(*lpTranslate).wLanguage,
			(*lpTranslate).wCodePage);

		// Retrieve the file version string for the language.
		if(!VerQueryValue(lpstrVffInfo, SubBlock, &lpBuffer, &dwBytes))
		{
			SeFree(lpstrVffInfo);
			return FALSE;
		}

		// Convert to ASCII
		TmpStr = SeCopyStr(lpBuffer);

		if(strlen(TmpStr) >= VersionBuffLen)
		{
			SeFree(lpstrVffInfo);
			SeFree(TmpStr);
			return FALSE;
		}

		SeStrCpy(VersionBuff, VersionBuffLen, TmpStr);

		SeFree(lpstrVffInfo);
		SeFree(TmpStr);

	} 
	else 
	{
		return FALSE;

	} 

	return TRUE;
}


bool Is64BitCode()
{
#ifdef	CPU_64
	return true;
#else	// CPU_64
	return false;
#endif	// CPU_64
}

bool IsWow64()
{
	bool b = false;

	if (Is64BitCode())
	{
		return false;
	}

	if (IsWow64Process(GetCurrentProcess(), &b) == false)
	{
		return false;
	}

	return b;
}

bool Is64BitWindows()
{
	if (Is64BitCode())
	{
		return true;
	}
	else
	{
		return IsWow64();
	}
}

void Win32NukuEn(char *dst, UINT size, char *src)
{
	char str[MAX_SIZE];
	int i;
	if (src)
	{
		SeStrCpy(str, sizeof(str), src);
	}
	else
	{
		SeStrCpy(str, sizeof(str), dst);
	}
	i = SeStrLen(str);
	if (str[i - 1] == '\\')
	{
		str[i - 1] = 0;
	}
	SeStrCpy(dst, size, str);
}

// Creating a lock
LOCK *NewLock()
{
	// Memory allocation
	LOCK *lock = SeMalloc(sizeof(LOCK));

	// Allocate a critical section
	CRITICAL_SECTION *critical_section = SeMalloc(sizeof(CRITICAL_SECTION));

	if (lock == NULL || critical_section == NULL)
	{
		SeFree(lock);
		SeFree(critical_section);
		return NULL;
	}

	// Initialize the critical section
	InitializeCriticalSection(critical_section);

	lock->pData = (void *)critical_section;
	lock->Ready = true;

	return lock;
}

// Lock
bool Lock(LOCK *lock)
{
	CRITICAL_SECTION *critical_section;
	if (lock->Ready == false)
	{
		// State is invalid
		return false;
	}

	// Enter the critical section
	critical_section = (CRITICAL_SECTION *)lock->pData;
	EnterCriticalSection(critical_section);

	return true;
}

// Unlock
void Unlock(LOCK *lock)
{
	UnlockEx(lock, false);
}
void UnlockEx(LOCK *lock, bool inner)
{
	CRITICAL_SECTION *critical_section;
	if (lock->Ready == false && inner == false)
	{
		// State is invalid
		return;
	}

	// Leave the critical section
	critical_section = (CRITICAL_SECTION *)lock->pData;
	LeaveCriticalSection(critical_section);
}

// Delete the lock
void DeleteLock(LOCK *lock)
{
	CRITICAL_SECTION *critical_section;
	// Reset the Ready flag safely
	Lock(lock);
	lock->Ready = false;
	UnlockEx(lock, true);

	// Delete the critical section
	critical_section = (CRITICAL_SECTION *)lock->pData;
	DeleteCriticalSection(critical_section);

	// Memory release
	SeFree(critical_section);
	SeFree(lock);
}

// Stop the service
bool MsStopService(char *name)
{
	SC_HANDLE sc, service;
	bool ret = false;
	// Validate arguments
	if (name == NULL)
	{
		return false;
	}

	sc = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (sc == NULL)
	{
		return false;
	}

	service = OpenService(sc, name, SERVICE_ALL_ACCESS);
	if (service != NULL)
	{
		SERVICE_STATUS st;
		ret = ControlService(service, SERVICE_CONTROL_STOP, &st);

		CloseServiceHandle(service);
	}

	if (ret)
	{
		UINT end = timeGetTime() + 10000;
		while (timeGetTime() < end)
		{
			if (MsIsServiceRunning(name) == false)
			{
				break;
			}

			Sleep(250);
		}
	}

	CloseServiceHandle(sc);
	return ret;
}

// Start the service
bool MsStartService(char *name)
{
	return MsStartServiceEx(name, NULL);
}
bool MsStartServiceEx(char *name, UINT *error_code)
{
	SC_HANDLE sc, service;
	bool ret = false;
	static UINT dummy = 0;
	// Validate arguments
	if (name == NULL)
	{
		return false;
	}
	if (error_code == NULL)
	{
		error_code = &dummy;
	}

	*error_code = 0;

	sc = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (sc == NULL)
	{
		*error_code = GetLastError();
		return false;
	}

	service = OpenService(sc, name, SERVICE_ALL_ACCESS);
	if (service != NULL)
	{
		ret = StartService(service, 0, NULL);

		CloseServiceHandle(service);
	}
	else
	{
		*error_code = GetLastError();
	}

	if (ret)
	{
		UINT end = timeGetTime() + 10000;
		while (timeGetTime() < end)
		{
			if (MsIsServiceRunning(name))
			{
				break;
			}

			Sleep(250);
		}
	}

	CloseServiceHandle(sc);
	return ret;
}

// Get whether the service is running
bool MsIsServiceRunning(char *name)
{
	SC_HANDLE sc, service;
	bool ret = false;
	// Validate arguments
	if (name == NULL || SeIsEmptyStr(name))
	{
		return false;
	}

	sc = OpenSCManager(NULL, NULL, GENERIC_READ);
	if (sc == NULL)
	{
		return false;
	}

	service = OpenService(sc, name, GENERIC_READ);
	if (service != NULL)
	{
		SERVICE_STATUS st;
		SeZero(&st, sizeof(st));
		if (QueryServiceStatus(service, &st))
		{
			switch (st.dwCurrentState)
			{
			case SERVICE_CONTINUE_PENDING:
			case SERVICE_PAUSE_PENDING:
			case SERVICE_PAUSED:
			case SERVICE_RUNNING:
			case SERVICE_START_PENDING:
			case SERVICE_STOP_PENDING:
				ret = true;
				break;
			}
		}

		CloseServiceHandle(service);
	}

	CloseServiceHandle(sc);
	return ret;
}

// Search for the adapter by GUID
MS_ADAPTER *MsGetAdapterByGuid(char *guid)
{
	MS_ADAPTER_LIST *o;
	MS_ADAPTER *ret = NULL;
	// Validate arguments
	if (guid == NULL)
	{
		return NULL;
	}

	o = MsCreateAdapterList();
	if (o == NULL)
	{
		return NULL;
	}

	ret = MsGetAdapterByGuidFromList(o, guid);

	MsFreeAdapterList(o);

	return ret;
}
MS_ADAPTER *MsGetAdapterByGuidFromList(MS_ADAPTER_LIST *o, char *guid)
{
	MS_ADAPTER *ret = NULL;
	UINT i;
	// Validate arguments
	if (o == NULL || guid == NULL)
	{
		return NULL;
	}

	for (i = 0;i < o->Num;i++)
	{
		if (SeStrCmpi(o->Adapters[i]->Guid, guid) == 0)
		{
			ret = MsCloneAdapter(o->Adapters[i]);
			break;
		}
	}

	return ret;
}

// Get a single adapter
MS_ADAPTER *MsGetAdapter(char *title)
{
	MS_ADAPTER_LIST *o;
	MS_ADAPTER *ret = NULL;
	UINT i;
	// Validate arguments
	if (title == NULL)
	{
		return NULL;
	}

	o = MsCreateAdapterList();
	if (o == NULL)
	{
		return NULL;
	}

	for (i = 0;i < o->Num;i++)
	{
		if (SeStrCmpi(o->Adapters[i]->Title, title) == 0)
		{
			ret = MsCloneAdapter(o->Adapters[i]);
			break;
		}
	}

	MsFreeAdapterList(o);

	return ret;
}

// 32-bit overflow checking
#define	CHECK_32BIT_OVERFLOW(old_value, new_value)				\
{																\
	if ((old_value) > (new_value))								\
{															\
	(new_value) += ((UINT64)4294967296ULL);					\
}															\
}

// Get the TCP/IP information of the specified adapter
void MsGetAdapterTcpIpInformation(MS_ADAPTER *a)
{
	IP_ADAPTER_INFO *info, *info_top;
	UINT info_size;
	UINT ret;
	// Validate arguments
	if (a == NULL)
	{
		return;
	}

	info_top = SeZeroMalloc(sizeof(IP_ADAPTER_INFO));
	info_size = sizeof(IP_ADAPTER_INFO);

	ret = GetAdaptersInfo(info_top, &info_size);
	if (ret == ERROR_INSUFFICIENT_BUFFER || ret == ERROR_BUFFER_OVERFLOW)
	{
		SeFree(info_top);
		info_size *= 2;
		info_top = SeZeroMalloc(info_size);

		if (GetAdaptersInfo(info_top, &info_size) != NO_ERROR)
		{
			SeFree(info_top);
			return;
		}
	}
	else if (ret != NO_ERROR)
	{
		SeFree(info_top);
		return;
	}

	// Search for their own entry
	info = info_top;

	while (info != NULL)
	{
		if (info->Index == a->Index)
		{
			IP_ADDR_STRING *s;

			// IP address
			a->NumIpAddress = 0;
			s = &info->IpAddressList;
			while (s != NULL)
			{
				if (a->NumIpAddress < MAX_MS_ADAPTER_IP_ADDRESS)
				{
					SeStrCpy(a->IpAddresses[a->NumIpAddress], MAX_PATH, s->IpAddress.String);
					SeStrCpy(a->SubnetMasks[a->NumIpAddress], MAX_PATH, s->IpMask.String);
					a->NumIpAddress++;
				}
				s = s->Next;
			}

			// Gateway
			a->NumGateway = 0;
			s = &info->GatewayList;
			while (s != NULL)
			{
				if (a->NumGateway < MAX_MS_ADAPTER_IP_ADDRESS)
				{
					SeStrCpy(a->Gateways[a->NumGateway], MAX_PATH, s->IpAddress.String);
					a->NumGateway++;
				}
				s = s->Next;
			}

			// DHCP Server
			a->UseDhcp = (info->DhcpEnabled == 0 ? false : true);
			if (a->UseDhcp)
			{
				s = &info->DhcpServer;
				SeStrCpy(a->DhcpServer, MAX_PATH, s->IpAddress.String);
			}

			// WINS server
			a->UseWins = info->HaveWins;
			if (a->UseWins)
			{
				SeStrCpy(a->PrimaryWinsServer, MAX_PATH, info->PrimaryWinsServer.IpAddress.String);
				SeStrCpy(a->SecondaryWinsServer, MAX_PATH, info->SecondaryWinsServer.IpAddress.String);
			}

			SeStrCpy(a->Guid, sizeof(a->Guid), info->AdapterName);

			a->Info = true;

			break;
		}

		info = info->Next;
	}

	SeFree(info_top);
}

static UINT last_adapter_tick = 0;

// Generation of adapter list
MS_ADAPTER_LIST *MsCreateAdapterList()
{
	return MsCreateAdapterListEx(false);
}
MS_ADAPTER_LIST *MsCreateAdapterListEx(bool no_info)
{
	MS_ADAPTER_LIST *ret;

	if (no_info)
	{
		ret = MsCreateAdapterListInnerEx(true);

		return ret;
	}

	Lock(lock_adapter_list);
	{
		MS_ADAPTER_LIST *old = last_adapter_list;
		UINT i;
		UINT now = timeGetTime();

		if (last_adapter_tick != 0 && old != NULL && ((UINT64)now <= ((UINT64)last_adapter_tick + (UINT64)3000)))
		{
			ret = MsCloneAdapterList(old);
		}
		else
		{
			// Fetch a new adapter list
			ret = MsCreateAdapterListInner();

			if (ret == NULL)
			{
				Unlock(lock_adapter_list);
				return NULL;
			}

			last_adapter_tick = now;

			// Check whether the previously acquired item exists for each entry
			// in the list of adapters have been taken
			for (i = 0;i < ret->Num;i++)
			{
				UINT j;
				for (j = 0;j < old->Num;j++)
				{
					MS_ADAPTER *o = old->Adapters[j];
					MS_ADAPTER *n = ret->Adapters[i];

					if (SeStrCmpi(o->Title, n->Title) == 0)
					{
						// If the value of older item is small, increment it
						CHECK_32BIT_OVERFLOW(o->RecvBytes, n->RecvBytes);
						CHECK_32BIT_OVERFLOW(o->RecvPacketsBroadcast, n->RecvPacketsBroadcast);
						CHECK_32BIT_OVERFLOW(o->RecvPacketsUnicast, n->RecvPacketsUnicast);
						CHECK_32BIT_OVERFLOW(o->SendBytes, n->SendBytes);
						CHECK_32BIT_OVERFLOW(o->SendPacketsBroadcast, n->SendPacketsBroadcast);
						CHECK_32BIT_OVERFLOW(o->SendPacketsUnicast, n->SendPacketsUnicast);
						break;
					}
				}
			}

			// Release the old adapter list
			MsFreeAdapterList(old);

			// Save a clone of the adapter list that newly acquired
			last_adapter_list = MsCloneAdapterList(ret);
		}
	}
	Unlock(lock_adapter_list);

	return ret;
}

// Initialization of the adapter module list
void MsInitAdapterListModule()
{
	lock_adapter_list = NewLock(NULL);

	last_adapter_list = MsCreateAdapterListInner();
}

// Release of the adapter module list
void MsFreeAdapterListModule()
{
	if (last_adapter_list != NULL)
	{
		MsFreeAdapterList(last_adapter_list);
		last_adapter_list = NULL;
	}

	DeleteLock(lock_adapter_list);
	lock_adapter_list = NULL;
}

// Clone the adapter list
MS_ADAPTER_LIST *MsCloneAdapterList(MS_ADAPTER_LIST *o)
{
	MS_ADAPTER_LIST *ret;
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return NULL;
	}

	ret = SeZeroMalloc(sizeof(MS_ADAPTER_LIST));
	ret->Num = o->Num;
	ret->Adapters = SeZeroMalloc(sizeof(MS_ADAPTER *) * ret->Num);

	for (i = 0;i < ret->Num;i++)
	{
		ret->Adapters[i] = SeZeroMalloc(sizeof(MS_ADAPTER));
		SeCopy(ret->Adapters[i], o->Adapters[i], sizeof(MS_ADAPTER));
	}

	return ret;
}

// Clone the adapter
MS_ADAPTER *MsCloneAdapter(MS_ADAPTER *a)
{
	MS_ADAPTER *ret;
	// Validate arguments
	if (a == NULL)
	{
		return NULL;
	}

	ret = SeZeroMalloc(sizeof(MS_ADAPTER));
	SeCopy(ret, a, sizeof(MS_ADAPTER));

	return ret;
}

// Creating an adapters list
MS_ADAPTER_LIST *MsCreateAdapterListInner()
{
	return MsCreateAdapterListInnerEx(false);
}
MS_ADAPTER_LIST *MsCreateAdapterListInnerEx(bool no_info)
{
	return MsCreateAdapterListInnerExVista(no_info);
}

// Creating an adapters list (Windows Vista version)
MS_ADAPTER_LIST *MsCreateAdapterListInnerExVista(bool no_info)
{
	SE_LIST *o;
	UINT i;
	UINT retcode;
	MIB_IF_TABLE2 *table;
	UINT table_size = sizeof(MIB_IFTABLE);
	MS_ADAPTER_LIST *ret;

	retcode = GetIfTable2(&table);
	if (retcode != NO_ERROR || table == NULL)
	{
		return SeZeroMalloc(sizeof(MS_ADAPTER_LIST));
	}

	o = SeNewList(NULL);

	for (i = 0;i < table->NumEntries;i++)
	{
		MIB_IF_ROW2 *r = &table->Table[i];
		wchar_t title[MAX_PATH];
		UINT num = 0;
		MS_ADAPTER *a;
		UINT j;

		//if (r->dwOperStatus == MIB_IF_OPER_STATUS_CONNECTED || r->dwOperStatus == MIB_IF_OPER_STATUS_OPERATIONAL)
		{
			//if (r->dwType & IF_TYPE_ETHERNET_CSMACD)
			{
				for (j = 1;;j++)
				{
					UINT k;
					bool exists;
					if (j == 1)
					{
						SeUniStrCpy(title, sizeof(title), r->Description);
					}
					else
					{
						wsprintfW(title, L"%s (%u)", r->Description, j);
					}

					exists = false;

					for (k = 0;k < SE_LIST_NUM(o);k++)
					{
						MS_ADAPTER *a = SE_LIST_DATA(o, k);

						if (SeUniStrCmpi(a->TitleW, title) == 0)
						{
							exists = true;
							break;
						}
					}

					if (exists == false)
					{
						break;
					}
				}

				a = SeZeroMalloc(sizeof(MS_ADAPTER));

				// Create an adapter information
				SeUniStrCpy(a->TitleW, sizeof(a->TitleW), title);
				SeUniToStr(a->Title, sizeof(a->Title), title);
				a->Index = r->InterfaceIndex;
				a->Type = r->Type;
				a->Status = ConvertMidStatusVistaToXp(r->OperStatus);
				a->Mtu = r->Mtu;
				a->Speed = MAX((UINT)r->TransmitLinkSpeed, (UINT)r->ReceiveLinkSpeed);
				a->AddressSize = MIN(sizeof(a->Address), r->PhysicalAddressLength);
				SeCopy(a->Address, r->PhysicalAddress, a->AddressSize);
				a->RecvBytes = r->InOctets;
				a->RecvPacketsBroadcast = r->InNUcastPkts;
				a->RecvPacketsUnicast = r->InUcastPkts;
				a->SendBytes = r->OutOctets;
				a->SendPacketsBroadcast = r->OutNUcastPkts;
				a->SendPacketsUnicast = r->OutUcastPkts;

				if (r->MediaType == NdisMediumWirelessWan || r->PhysicalMediumType == NdisPhysicalMediumWirelessLan ||
					r->PhysicalMediumType == NdisPhysicalMediumWirelessWan || r->PhysicalMediumType == NdisPhysicalMediumWiMax ||
					r->Type == IF_TYPE_IEEE80211)
				{
					a->IsWireless = true;
				}

				if (a->IsWireless ||
					r->Type != IF_TYPE_ETHERNET_CSMACD ||
					r->MediaType != NdisMedium802_3 || 
					(r->PhysicalMediumType != 0 && r->PhysicalMediumType != NdisPhysicalMedium802_3))
				{
					a->IsNotEthernetLan = true;
				}

				// TCP/IP information acquisition
				if (no_info == false)
				{
					MsGetAdapterTcpIpInformation(a);
				}

				SeAdd(o, a);
			}
		}
	}

	ret = SeZeroMalloc(sizeof(MS_ADAPTER_LIST));
	ret->Num = SE_LIST_NUM(o);
	ret->Adapters = SeToArray(o);

	SeFreeList(o);
	FreeMibTable(table);

	return ret;
}

// Convert the MIB Operational Status from Vista format to XP format
UINT ConvertMidStatusVistaToXp(UINT st)
{
	switch (st)
	{
	case IfOperStatusUp:
		return MIB_IF_OPER_STATUS_CONNECTED;

	case IfOperStatusDown:
		return MIB_IF_OPER_STATUS_DISCONNECTED;
	}

	return MIB_IF_OPER_STATUS_NON_OPERATIONAL;
}

// Release the adapter list
void MsFreeAdapterList(MS_ADAPTER_LIST *o)
{
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < o->Num;i++)
	{
		MsFreeAdapter(o->Adapters[i]);
	}
	SeFree(o->Adapters);

	SeFree(o);
}

// Release the adapter information
void MsFreeAdapter(MS_ADAPTER *a)
{
	// Validate arguments
	if (a == NULL)
	{
		return;
	}

	SeFree(a);
}

// Get the status string of the adapter
wchar_t *MsGetAdapterStatusStr(UINT status)
{
	wchar_t *ret;

	switch (status)
	{
	case MIB_IF_OPER_STATUS_NON_OPERATIONAL:
		ret = L"MIB_IF_OPER_STATUS_NON_OPERATIONAL";
		break;

	case MIB_IF_OPER_STATUS_UNREACHABLE:
		ret = L"MIB_IF_OPER_STATUS_UNREACHABLE";
		break;

	case MIB_IF_OPER_STATUS_DISCONNECTED:
		ret = L"MIB_IF_OPER_STATUS_DISCONNECTED";
		break;

	case MIB_IF_OPER_STATUS_CONNECTING:
		ret = L"MIB_IF_OPER_STATUS_CONNECTING";
		break;

	case MIB_IF_OPER_STATUS_CONNECTED:
		ret = L"MIB_IF_OPER_STATUS_CONNECTED";
		break;

	default:
		ret = L"OK";
		break;
	}

	return ret;
}

// Get the type string of the adapter
wchar_t *MsGetAdapterTypeStr(UINT type)
{
	wchar_t *ret;

	switch (type)
	{
	case MIB_IF_TYPE_ETHERNET:
		ret = L"MIB_IF_TYPE_ETHERNET";
		break;

	case IF_TYPE_IEEE80211:
		ret = L"IF_TYPE_IEEE80211";
		break;

	case MIB_IF_TYPE_TOKENRING:
		ret = L"MIB_IF_TYPE_TOKENRING";
		break;

	case MIB_IF_TYPE_FDDI:
		ret = L"MIB_IF_TYPE_FDDI";
		break;

	case MIB_IF_TYPE_PPP:
		ret = L"MIB_IF_TYPE_PPP";
		break;

	case MIB_IF_TYPE_LOOPBACK:
		ret = L"MIB_IF_TYPE_LOOPBACK";
		break;

	case MIB_IF_TYPE_SLIP:
		ret = L"MIB_IF_TYPE_SLIP";
		break;

	default:
		ret = L"Other";
		break;
	}

	return ret;
}

