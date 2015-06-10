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
#include <winsock2.h>
#include <windows.h>
#include <Dbghelp.h>
#include <commctrl.h>
#include <process.h>
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

// Write the next packet to the driver
bool SuPutPacket(SU_ADAPTER *a, void *buf, UINT size)
{
	// Validate arguments
	if (a == NULL)
	{
		return false;
	}
	if (a->Halt)
	{
		return false;
	}
	if (size > SL_MAX_PACKET_SIZE)
	{
		return false;
	}

	// First, examine whether the current buffer is full
	if ((SL_NUM_PACKET(a->PutBuffer) >= SL_MAX_PACKET_EXCHANGE) ||
		(buf == NULL && SL_NUM_PACKET(a->PutBuffer) != 0))
	{
		// Write all current packets to the driver
		if (SuPutPacketsToDriver(a) == false)
		{
			return false;
		}

		SL_NUM_PACKET(a->PutBuffer) = 0;
	}

	// Add the next packet to the buffer
	if (buf != NULL)
	{
		UINT i = SL_NUM_PACKET(a->PutBuffer);
		SL_NUM_PACKET(a->PutBuffer)++;

		SL_SIZE_OF_PACKET(a->PutBuffer, i) = size;
		SeCopy(SL_ADDR_OF_PACKET(a->PutBuffer, i), buf, size);

		SeFree(buf);
	}

	return true;
}

// Write all current packets to the driver
bool SuPutPacketsToDriver(SU_ADAPTER *a)
{
	DWORD write_size;
	// Validate arguments
	if (a == NULL)
	{
		return false;
	}
	if (a->Halt)
	{
		return false;
	}

	if (WriteFile(a->hFile, a->PutBuffer, SL_EXCHANGE_BUFFER_SIZE, &write_size, NULL) == false)
	{
		a->Halt = true;

		SuCloseAdapterHandleInner(a);
		return false;
	}

	if (write_size != SL_EXCHANGE_BUFFER_SIZE)
	{
		a->Halt = true;
		return false;
	}

	return true;
}

// Peek the next packet from the driver
UINT SuPeekNextPacket(SU_ADAPTER *a)
{
	// Validate arguments
	if (a == NULL)
	{
		return 0;
	}

	if (a->Halt)
	{
		return 0;
	}

	if (a->CurrentPacketCount < SL_NUM_PACKET(a->GetBuffer))
	{
		return SL_SIZE_OF_PACKET(a->GetBuffer, a->CurrentPacketCount);
	}

	if (SuGetPacketsFromDriver(a) == false)
	{
		return 0;
	}

	if (SL_NUM_PACKET(a->GetBuffer) == 0)
	{
		// Packet is not received yet
		return 0;
	}

	a->CurrentPacketCount = 0;

	if (a->CurrentPacketCount < SL_NUM_PACKET(a->GetBuffer))
	{
		return SL_SIZE_OF_PACKET(a->GetBuffer, a->CurrentPacketCount);
	}

	return 0;
}

// Read the next packet from the driver
bool SuGetNextPacket(SU_ADAPTER *a, void **buf, UINT *size, SL_TIMEVAL *timestamp)
{
	// Validate arguments
	if (a == NULL || buf == NULL || size == NULL)
	{
		return false;
	}

	if (a->Halt)
	{
		return false;
	}

	while (true)
	{
		if (a->CurrentPacketCount < SL_NUM_PACKET(a->GetBuffer))
		{
			// There are still packets that have been already read
			*size = SL_SIZE_OF_PACKET(a->GetBuffer, a->CurrentPacketCount);
			*buf = SeMalloc(*size);
			SeCopy(*buf, SL_ADDR_OF_PACKET(a->GetBuffer, a->CurrentPacketCount), *size);
			SeCopy(timestamp, SL_TIMESTAMP_OF_PACKET(a->GetBuffer, a->CurrentPacketCount), sizeof(SL_TIMEVAL));

			// Increment the packet number
			a->CurrentPacketCount++;

			a->Stat_Recv++;
			a->Stat_Capt++;

			return true;
		}
		else
		{
			// Read the next packet from the driver
			if (SuGetPacketsFromDriver(a) == false)
			{
				return false;
			}

			if (SL_NUM_PACKET(a->GetBuffer) == 0)
			{
				// Packet is not received yet
				*buf = NULL;
				*size = 0;
				return true;
			}

			a->CurrentPacketCount = 0;
		}
	}
}

// Read the next packet from the driver
bool SuGetPacketsFromDriver(SU_ADAPTER *a)
{
	DWORD read_size;
	// Validate arguments
	if (a == NULL)
	{
		return false;
	}

	if (a->Halt)
	{
		return false;
	}

	if (ReadFile(a->hFile, a->GetBuffer, SL_EXCHANGE_BUFFER_SIZE, &read_size, NULL) == false)
	{
		a->Halt = true;

		SuCloseAdapterHandleInner(a);
		return false;
	}

	if (read_size != SL_EXCHANGE_BUFFER_SIZE)
	{
		a->Halt = true;
		return false;
	}

	return true;
}

// Close the adapter
void SuCloseAdapter(SU_ADAPTER *a)
{
	// Validate arguments
	if (a == NULL)
	{
		return;
	}

	if (a->hEvent != NULL)
	{
		CloseHandle(a->hEvent);
	}

	if (a->hFile != INVALID_HANDLE_VALUE)
	{
		CloseHandle(a->hFile);
		a->hFile = INVALID_HANDLE_VALUE;
	}

	SeFree(a);
}

// Close the adapter handle
void SuCloseAdapterHandleInner(SU_ADAPTER *a)
{
	return;//////////// ****************
	// Validate arguments
	if (a == NULL)
	{
		return;
	}

	if (a->hFile != INVALID_HANDLE_VALUE)
	{
		CloseHandle(a->hFile);
		a->hFile = INVALID_HANDLE_VALUE;
	}
}

// Open the adapter
SU_ADAPTER *SuOpenAdapter(SU *u, char *adapter_id)
{
	char filename[MAX_PATH];
	void *h;
	SU_ADAPTER *a;
	SL_IOCTL_EVENT_NAME t;
	UINT read_size;
	// Validate arguments
	if (u == NULL || adapter_id == NULL)
	{
		return NULL;
	}

	_snprintf_s(filename, sizeof(filename), _TRUNCATE, SL_ADAPTER_DEVICE_FILENAME_WIN32, adapter_id);

	h = CreateFileA(filename, GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (h == INVALID_HANDLE_VALUE)
	{
		return NULL;
	}

	a = SeZeroMalloc(sizeof(SU_ADAPTER));

	SeStrCpy(a->AdapterId, sizeof(a->AdapterId), adapter_id);
	SeStrCpy(a->DeviceName, sizeof(a->DeviceName), filename);

	a->hFile = h;

	SeZero(&t, sizeof(t));

	// Get the event name
	if (DeviceIoControl(h, SL_IOCTL_GET_EVENT_NAME, &t, sizeof(t), &t, sizeof(t), &read_size, NULL) == false)
	{
		// Acquisition failure
		SuCloseAdapter(a);
		return NULL;
	}

	// Get the event
	a->hEvent = OpenEvent(EVENT_ALL_ACCESS, FALSE, t.EventNameWin32);

	if (a->hEvent == NULL)
	{
		// Acquisition failure
		SuCloseAdapter(a);
		return NULL;
	}

	return a;
}

// Enumerate adapters
SU_ADAPTER_NAMES_LIST *SuEnumAdapters(SU *u)
{
	UINT i;
	UINT ret_size;
	SU_ADAPTER_NAMES_LIST *ret;
	// Validate arguments
	if (u == NULL)
	{
		return SeZeroMalloc(sizeof(SU_ADAPTER_NAMES_LIST));
	}

	SeZero(&u->AdapterInfoList, sizeof(u->AdapterInfoList));
	if (ReadFile(u->hFile, &u->AdapterInfoList, sizeof(u->AdapterInfoList),
		&ret_size, NULL) == false ||
		u->AdapterInfoList.Signature != SL_SIGNATURE)
	{
		return SeZeroMalloc(sizeof(SU_ADAPTER_NAMES_LIST));
	}

	ret = SeZeroMalloc(sizeof(SU_ADAPTER_NAMES_LIST));

	ret->NumTokens = u->AdapterInfoList.NumAdapters;
	ret->Token = SeZeroMalloc(sizeof(char *) * ret->NumTokens);

	for (i = 0;i < ret->NumTokens;i++)
	{
		ret->Token[i] = WChar2SChar(u->AdapterInfoList.Adapters[i].AdapterId);
	}

	return ret;
}

// Create an adapters list
SE_LIST *SuGetAdapterList(SU *u)
{
	SE_LIST *ret;
	UINT read_size;
	UINT i;
	// Validate arguments
	if (u == NULL)
	{
		return NULL;
	}

	ret = SeNewList(SuCmpAdaterList);

	// Enumerate adapters
	SeZero(&u->AdapterInfoList, sizeof(u->AdapterInfoList));
	if (ReadFile(u->hFile, &u->AdapterInfoList, sizeof(u->AdapterInfoList),
		&read_size, NULL) == false ||
		u->AdapterInfoList.Signature != SL_SIGNATURE)
	{
		SuFreeAdapterList(ret);
		return NULL;
	}

	for (i = 0;i < u->AdapterInfoList.NumAdapters;i++)
	{
		SL_ADAPTER_INFO *info = &u->AdapterInfoList.Adapters[i];
		SU_ADAPTER_LIST *a = SuAdapterInfoToAdapterList(info);

		if (a != NULL)
		{
			SeAdd(ret, a);
		}
	}

	// Sort
	SeSort(ret);

	return ret;
}

// Comparison function of the adapter list
int SuCmpAdaterList(void *p1, void *p2)
{
	int r;
	SU_ADAPTER_LIST *a1, *a2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	a1 = *(SU_ADAPTER_LIST **)p1;
	a2 = *(SU_ADAPTER_LIST **)p2;
	if (a1 == NULL || a2 == NULL)
	{
		return 0;
	}

	r = SeStrCmpi(a1->SortKey, a2->SortKey);
	if (r != 0)
	{
		return 0;
	}

	return SeStrCmpi(a1->Guid, a2->Guid);
}

// Release the adapter list
void SuFreeAdapterList(SE_LIST *o)
{
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < SE_LIST_NUM(o);i++)
	{
		SU_ADAPTER_LIST *a = SE_LIST_DATA(o, i);

		SeFree(a);
	}

	SeFreeList(o);
}

// Create an adapter list item
SU_ADAPTER_LIST *SuAdapterInfoToAdapterList(SL_ADAPTER_INFO *info)
{
	SU_ADAPTER_LIST t;
	char tmp[MAX_SIZE];
	char *tmp2;
	// Validate arguments
	if (info == NULL)
	{
		return NULL;
	}

	SeZero(tmp, sizeof(tmp));
	SeZero(&t, sizeof(t));
	SeCopy(&t.Info, info, sizeof(SL_ADAPTER_INFO));

	tmp2 = WChar2SChar(info->AdapterId);
	SeStrCpy(tmp, sizeof(tmp), tmp2);
	SeFree(tmp2);
	if (SeIsEmptyStr(tmp) || SeIsEmptyStr(info->FriendlyName) || SeStartWith(tmp, SL_ADAPTER_ID_PREFIX) == false)
	{
		// Name is invalid
		return NULL;
	}

	// GUID (Part after "WTCAP_A_" prefix)
	SeStrCpy(t.Guid, sizeof(t.Guid), tmp + SeStrLen(SL_ADAPTER_ID_PREFIX));

	// Name
	SeStrCpy(t.Name, sizeof(t.Name), tmp);

	// Name Replaced
	_snprintf_s(t.Name_Replaced, sizeof(t.Name_Replaced), _TRUNCATE,
		"%s", t.Guid);

	/*
	// Key for sort
	if (GetClassRegKeyWin32(t.SortKey, sizeof(t.SortKey), tmp, sizeof(tmp), t.Guid) == false)
	{
		// Can not be found
		return NULL;
	}*/

	return SeClone(&t, sizeof(t));
}

// Initialize the driver 
SU *SuInit()
{
	return SuInitEx(0);
}
SU *SuInitEx(UINT wait_for_bind_complete_tick)
{
	void *h;
	SU *u;
	UINT read_size;
	UINT giveup_tick = 0;
	bool flag = false;

LABEL_RETRY:

	// Open the device driver
	h = CreateFileA(SL_BASIC_DEVICE_FILENAME_WIN32, GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (h == INVALID_HANDLE_VALUE)
	{
		// Start the service if it fails to start the device driver
		if (flag == false && MsStartService(SL_PROTOCOL_NAME))
		{
			flag = true;
			goto LABEL_RETRY;
		}

		return NULL;
	}

	//Debug("CreateFileA(%s) Ok.\n", SL_BASIC_DEVICE_FILENAME_WIN32);

	u = SeZeroMalloc(sizeof(SU));

	giveup_tick = timeGetTime() + wait_for_bind_complete_tick;

	if (wait_for_bind_complete_tick == 0)
	{
		if (ReadFile(h, &u->AdapterInfoList, sizeof(u->AdapterInfoList), &read_size, NULL) == false ||
			u->AdapterInfoList.Signature != SL_SIGNATURE)
		{
			// Signature reception failure
			SeFree(u);
			CloseHandle(h);

			return NULL;
		}
	}
	else
	{
		while (giveup_tick >= timeGetTime())
		{
			// Wait until the enumeration is completed
			if (ReadFile(h, &u->AdapterInfoList, sizeof(u->AdapterInfoList), &read_size, NULL) == false ||
				u->AdapterInfoList.Signature != SL_SIGNATURE)
			{
				// Signature reception failure

				SeFree(u);
				CloseHandle(h);

				return NULL;
			}

			if (u->AdapterInfoList.EnumCompleted >= 8)
			{
				// Complete enumeration
				break;
			}

			// Incomplete enumeration
			Sleep(25);
		}
	}

	u->hFile = h;

	return u;
}

// Release the driver
void SuFree(SU *u)
{
	// Validate arguments
	if (u == NULL)
	{
		return;
	}

	CloseHandle(u->hFile);

	SeFree(u);
}
