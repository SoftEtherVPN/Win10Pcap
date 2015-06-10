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

#define SE_INTERNAL

#define	_WIN32_WINNT		0x0502
#define	WINVER				0x0502
#include <winsock2.h>
#include <Ws2tcpip.h>
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
#include "win_bpf.h"
#include "Packet32.h"
#include "NdisDriverUser.h"
#include "Packet32_Internal.h"
#include "Ms.h"

static char driver_file_version[MAX_PATH] = {0};
static LOCK *su_lock = NULL;
static SU *su_basic = NULL;


BOOL APIENTRY DllMain(HANDLE DllHandle, DWORD Reason, LPVOID lpReserved)
{
	bool ret = true;
	void *fs = NULL;

	switch(Reason)
	{
	case DLL_PROCESS_ATTACH:
		SeStrCpy(driver_file_version, sizeof(driver_file_version), "Unknown");

		fs = DisableWow64FsRedirection();

		MsGetFileVersion("drivers\\Win10Pcap.sys", driver_file_version, sizeof(driver_file_version));

		RestoreWow64FsRedirection(fs);

		su_lock = NewLock();

		MsInitAdapterListModule();

		break;

	case DLL_PROCESS_DETACH:

		DeleteLock(su_lock);
		su_lock = NULL;

		FreeSuBasicAdapter();

		MsFreeAdapterListModule();

		break;
	}

	return ret;
}

void FreeSuBasicAdapter()
{
	if (su_basic != NULL)
	{
		SuFree(su_basic);
		su_basic = NULL;
	}
}

SU *OpenSuBasicAdapter()
{
	if (su_lock == NULL)
	{
		return NULL;
	}

	if (su_basic != NULL)
	{
		return su_basic;
	}

	Lock(su_lock);
	{
		if (su_basic == NULL)
		{
			su_basic = SuInitEx(180 * 100);
		}
	}
	Unlock(su_lock);

	return su_basic;
}


PCHAR PacketLibraryVersion()
{
	return PACKET_CURRENT_VERSION;
}

PCHAR WChar2SChar(PWCHAR string)
{
	PCHAR TmpStr;
	TmpStr = (CHAR*) SeZeroMalloc((UINT)((wcslen(string)+1) * sizeof(wchar_t)));

	// Conver to ASCII
	WideCharToMultiByte(
		CP_ACP,
		0,
		string,
		-1,
		TmpStr,
		((int)(wcslen(string)+1) * sizeof(wchar_t)),          // size of buffer
		NULL,
		NULL);

	return TmpStr;
}

PCHAR PacketGetVersion()
{
	return PACKET_CURRENT_VERSION;
}

PCHAR PacketGetDriverVersion()
{
	return driver_file_version;
}

BOOLEAN PacketSetMinToCopy(LPADAPTER AdapterObject,int nbytes)
{
	return true;
}

BOOLEAN PacketSetNumWrites(LPADAPTER AdapterObject,int nwrites)
{
	return false;
}

BOOLEAN PacketSetMode(LPADAPTER AdapterObject,int mode)
{
	SU_ADAPTER *a;

	if (AdapterObject == NULL)
	{
		return false;
	}

	a = (SU_ADAPTER *)AdapterObject->hFile;

	switch (mode)
	{
	case PACKET_MODE_CAPT:
		return true;

	default:
		return false;
	}
}

BOOLEAN PacketSetReadTimeout(LPADAPTER AdapterObject,int timeout)
{
	SU_ADAPTER *a;

	if (AdapterObject == NULL)
	{
		return false;
	}

	if (timeout == -1)
	{
		timeout = 0;
	}

	a = (SU_ADAPTER *)AdapterObject->hFile;

	AdapterObject->CurrentTimeout = timeout;

	return TRUE;
}

BOOLEAN PacketSetBpf(LPADAPTER AdapterObject,struct bpf_program *fp)
{
	struct bpf_program *clone = NULL;
	if (AdapterObject == NULL)
	{
		return false;
	}

	if (fp != NULL)
	{
		clone = SeZeroMalloc(sizeof(struct bpf_program));
		clone->bf_len = fp->bf_len;
		clone->bf_insns = SeClone(fp->bf_insns, sizeof(struct bpf_insn) * clone->bf_len);
	}

	Lock(AdapterObject->FilterLock);
	{
		if (AdapterObject->Filter != NULL)
		{
			SeFree(AdapterObject->Filter->bf_insns);
			SeFree(AdapterObject->Filter);
		}

		AdapterObject->Filter = clone;
	}
	Unlock(AdapterObject->FilterLock);

	return true;
}

BOOLEAN PacketSetLoopbackBehavior(LPADAPTER  AdapterObject, UINT LoopbackBehavior)
{
	return false;
}

VOID *PacketGetAirPcapHandle(LPADAPTER AdapterObject)
{
	return NULL;
}

INT PacketSetSnapLen(LPADAPTER AdapterObject,int snaplen)
{
	return 0;
}

BOOLEAN PacketGetStats(LPADAPTER AdapterObject,struct bpf_stat *s)
{
	SU_ADAPTER *a;
	if (AdapterObject == NULL)
	{
		return false;
	}

	a = (SU_ADAPTER *)AdapterObject->hFile;

	s->ps_ifdrop = 0;
	s->bs_capt = a->Stat_Capt;
	s->bs_drop = 0;
	s->bs_recv = a->Stat_Recv;

	return true;
}

BOOLEAN PacketGetStatsEx(LPADAPTER AdapterObject,struct bpf_stat *s)
{
	return PacketGetStats(AdapterObject, s);
}

BOOLEAN PacketSetBuff(LPADAPTER AdapterObject,int dim)
{
	return true;
}

BOOLEAN PacketGetNetType (LPADAPTER AdapterObject,NetType *type)
{
	type->LinkSpeed = 1000000000;
	type->LinkType = 0;

	return true;
}

LPADAPTER PacketOpenAdapter(PCHAR AdapterName)
{
	SU *su = OpenSuBasicAdapter();
	SU_ADAPTER *a;
	ADAPTER *ret;
	SE_LIST *o;
	SU_ADAPTER_LIST *d;
	char target_adapter_name[MAX_PATH] = {0};

	if (su == NULL)
	{
		return NULL;
	}

	o = SuGetAdapterList(su);

	d = FindAdapterByName(o, AdapterName);

	if (d != NULL)
	{
		SeStrCpy(target_adapter_name, sizeof(target_adapter_name), d->Name);
	}

	SuFreeAdapterList(o);

	if (SeIsEmptyStr(target_adapter_name))
	{
		return NULL;
	}

	a = SuOpenAdapter(su, target_adapter_name);
	if (a == NULL)
	{
		return NULL;
	}

	ret = SeZeroMalloc(sizeof(ADAPTER));
	ret->FilterLock = NewLock();
	SeStrCpy(ret->SymbolicLink, sizeof(ret->SymbolicLink), a->DeviceName);
	SeStrCpy(ret->Name, sizeof(ret->Name), a->AdapterId);
	ret->hFile = (HANDLE)a;
	ret->ReadEvent = a->hEvent;

	return ret;
}

SU_ADAPTER_LIST *FindAdapterByName(SE_LIST *o, char *name)
{
	UINT i;

	for (i = 0;i < SE_LIST_NUM(o);i++)
	{
		SU_ADAPTER_LIST *d = SE_LIST_DATA(o, i);

		if (SeStrCmpi(d->Name_Replaced, name) == 0)
		{
			return d;
		}
	}

	return NULL;
}

BOOLEAN PacketSendPacket(LPADAPTER AdapterObject,LPPACKET pPacket,BOOLEAN Sync)
{
	SU_ADAPTER *a;
	if (AdapterObject == NULL || pPacket == NULL)
	{
		return false;
	}

	a = (SU_ADAPTER *)AdapterObject->hFile;

	if (SuPutPacket(a, pPacket->Buffer, pPacket->Length) == false)
	{
		return false;
	}

	if (SuPutPacket(a, NULL, 0) == false)
	{
		return false;
	}

	return true;
}

INT PacketSendPackets(LPADAPTER AdapterObject,PVOID PacketBuff,ULONG Size, BOOLEAN Sync)
{
	SU_ADAPTER *a;
	PCHAR UserBuff = PacketBuff;
	ULONG UserBuffSize = Size;
	sf_pkthdr *winpcap_hdr;
	PCHAR EndOfUserBuff = UserBuff + UserBuffSize;
	if (AdapterObject == NULL || PacketBuff == NULL || Size == 0)
	{
		return false;
	}

	a = (SU_ADAPTER *)AdapterObject->hFile;

	winpcap_hdr = (struct sf_pkthdr*)UserBuff;

	if( (PCHAR)winpcap_hdr + winpcap_hdr->caplen + sizeof(struct sf_pkthdr) > EndOfUserBuff )
	{
		return -1;
	}

	while (true)
	{
		UCHAR *packet_ptr;
		UINT packet_size;

		if (winpcap_hdr->caplen == 0)
		{
			return -1;
		}

		packet_ptr = (PCHAR)winpcap_hdr + sizeof(struct sf_pkthdr);
		packet_size = winpcap_hdr->caplen;

		if (SuPutPacket(a, packet_ptr, packet_size) == false)
		{
			return -1;
		}

		(PCHAR)winpcap_hdr += winpcap_hdr->caplen + sizeof(struct sf_pkthdr);
		if( (PCHAR)winpcap_hdr >= EndOfUserBuff )
		{
			break;
		}
	}

	if (SuPutPacket(a, NULL, 0) == false)
	{
		return -1;
	}

	return (INT)((PCHAR)winpcap_hdr - UserBuff);
}

LPPACKET PacketAllocatePacket(void)
{
	LPPACKET    lpPacket;
	lpPacket=(LPPACKET)SeZeroMalloc(sizeof(PACKET));
	if (lpPacket==NULL)
	{
		return NULL;
	}
	return lpPacket;
}

VOID PacketInitPacket(LPPACKET lpPacket,PVOID  Buffer,UINT  Length)
{
	lpPacket->Buffer = Buffer;
	lpPacket->Length = Length;
	lpPacket->ulBytesReceived = 0;
	lpPacket->bIoComplete = FALSE;
}

VOID PacketFreePacket(LPPACKET lpPacket)
{
	SeFree(lpPacket);
}

BOOLEAN PacketReceivePacket(LPADAPTER AdapterObject,LPPACKET lpPacket,BOOLEAN Sync)
{
	SU_ADAPTER *a;
	UINT current_offset;
	UCHAR *write_buffer;
	if (AdapterObject == NULL || lpPacket == NULL)
	{
		return false;
	}

	lpPacket->ulBytesReceived = 0;

	a = (SU_ADAPTER *)AdapterObject->hFile;
	if (a == NULL || a->Halt)
	{
		return false;
	}

	current_offset = 0;
	write_buffer = (UCHAR *)lpPacket->Buffer;
	if (write_buffer == NULL)
	{
		return false;
	}

	if (AdapterObject->CurrentTimeout != 0)
	{
		UINT next_packet_size = SuPeekNextPacket(a);

		if (next_packet_size == 0)
		{
			WaitForSingleObject(a->hEvent, AdapterObject->CurrentTimeout);
		}
	}

	while (true)
	{
		UINT next_packet_size = SuPeekNextPacket(a);
		UINT next_packet_need_size = 0;
		UINT bpf_header_size_with_padding = Packet_WORDALIGN(sizeof(struct bpf_hdr));
		UCHAR *su_buf = NULL;
		UINT su_size = 0;
		SL_TIMEVAL timestamp;
		struct bpf_hdr *header;

		if (next_packet_size == 0)
		{
			break;
		}

		next_packet_need_size = Packet_WORDALIGN(bpf_header_size_with_padding + next_packet_size);

		if (lpPacket->Length < (current_offset + next_packet_need_size))
		{
			break;
		}

		if (SuGetNextPacket(a, &su_buf, &su_size, &timestamp) == false)
		{
			return false;
		}

		if (su_buf == NULL)
		{
			break;
		}

		if (CheckFilter(AdapterObject, su_buf, su_size))
		{
			header = (struct bpf_hdr *)(write_buffer + current_offset);
			header->bh_caplen = header->bh_datalen = su_size;
			SeCopy(&header->bh_tstamp, &timestamp, sizeof(SL_TIMEVAL));
			header->bh_hdrlen = bpf_header_size_with_padding;

			current_offset += bpf_header_size_with_padding;
			SeCopy(write_buffer + current_offset, su_buf, su_size);

			current_offset += (next_packet_need_size - bpf_header_size_with_padding);
		}

		SeFree(su_buf);
	}

	lpPacket->ulBytesReceived = current_offset;

	return true;
}

BOOLEAN PacketSetHwFilter(LPADAPTER AdapterObject,ULONG Filter)
{
	return true;
}

BOOLEAN PacketGetAdapterNames(PTSTR pStr,PULONG  BufferSize)
{
	SU *su = OpenSuBasicAdapter();
	SE_LIST *o;
	UINT i;
	ULONG	SizeNeeded = 1;
	ULONG	SizeNames = 1;
	ULONG	SizeDesc;
	ULONG	OffDescriptions;

	if (su == NULL)
	{
		return false;
	}

	o = SuGetAdapterList(su);
	if (o == NULL)
	{
		return false;
	}

	for (i = 0;i < SE_LIST_NUM(o);i++)
	{
		SU_ADAPTER_LIST *d = SE_LIST_DATA(o, i);
		SizeNeeded += (int)strlen(d->Name_Replaced) + (int)strlen(d->Info.FriendlyName) + 2;
		SizeNames += (int)strlen(d->Name_Replaced) + 1;
	}

	if(SizeNeeded + 2 >= *BufferSize || pStr == NULL)
	{
		*BufferSize = SizeNeeded + 4;  // Report the required size

		if (pStr != NULL)
		{
			return FALSE;
		}
		else
		{
			return TRUE;
		}
	}

	SeZero(pStr, *BufferSize);

	OffDescriptions = SizeNames;

	SizeNames = 0;
	SizeDesc = 0;

	for (i = 0;i < SE_LIST_NUM(o);i++)
	{
		SU_ADAPTER_LIST *d = SE_LIST_DATA(o, i);

		// Copy the data
		SeStrCpy(((PCHAR)pStr) + SizeNames, 0, d->Name_Replaced);
		SeStrCpy(((PCHAR)pStr) + OffDescriptions + SizeDesc, 0, d->Info.FriendlyName);

		// Update the size variables
		SizeNames += (int)strlen(d->Name_Replaced) + 1;
		SizeDesc += (int)strlen(d->Info.FriendlyName) + 1;
	}

	SuFreeAdapterList(o);

	return true;
}

BOOLEAN PacketGetNetInfoEx(PCHAR AdapterName, npf_if_addr* buffer, PLONG NEntries)
{
	SU *su = OpenSuBasicAdapter();
	SE_LIST *o;
	SU_ADAPTER_LIST *d;
	bool ret = false;

	if (su == NULL)
	{
		return false;
	}

	o = SuGetAdapterList(su);

	d = FindAdapterByName(o, AdapterName);

	if (d != NULL)
	{
		MS_ADAPTER *a = MsGetAdapterByGuid(d->Guid);

		if (a != NULL)
		{
			UINT num = MIN(MAX_MS_ADAPTER_IP_ADDRESS, (UINT)(*NEntries));
			UINT i;
			UINT num_ret = 0;

			for (i = 0;i < num;i++)
			{
				if (SeIsEmptyStr(a->IpAddresses[i]) == false)
				{
					struct addrinfo hint;
					struct addrinfo *info;

					SeZero(&hint, sizeof(hint));
					hint.ai_family = AF_UNSPEC;
					hint.ai_socktype = SOCK_DGRAM;
					hint.ai_protocol = IPPROTO_UDP;
					info = NULL;

					if (getaddrinfo(a->IpAddresses[i], NULL, &hint, &info) == 0)
					{
						struct sockaddr_storage ss;
						SeZero(&ss, sizeof(ss));

						SeCopy(&ss, info->ai_addr, (UINT)info->ai_addrlen);

						SeZero(&buffer[num_ret], sizeof(struct sockaddr_storage));
						SeCopy(&buffer[num_ret].IPAddress, &ss, sizeof(struct sockaddr_storage));
						num_ret++;
					}
				}
			}

			*NEntries = num_ret;

			MsFreeAdapter(a);

			ret = true;
		}
	}

	SuFreeAdapterList(o);

	return ret;
}

BOOLEAN PacketRequest(LPADAPTER  AdapterObject,BOOLEAN Set,PPACKET_OID_DATA  OidData)
{
	return false;
}

HANDLE PacketGetReadEvent(LPADAPTER AdapterObject)
{
	SU_ADAPTER *a;
	if (AdapterObject == NULL)
	{
		return false;
	}

	a = (SU_ADAPTER *)AdapterObject->hFile;
	if (a->Halt)
	{
		return false;
	}

	return a->hEvent;
}

BOOLEAN PacketSetDumpName(LPADAPTER AdapterObject, void *name, int len)
{
	return false;
}

BOOLEAN PacketSetDumpLimits(LPADAPTER AdapterObject, UINT maxfilesize, UINT maxnpacks)
{
	return false;
}

BOOLEAN PacketIsDumpEnded(LPADAPTER AdapterObject, BOOLEAN sync)
{
	return false;
}

BOOL PacketStopDriver()
{
	return false;
}

VOID PacketCloseAdapter(LPADAPTER lpAdapter)
{
	if (lpAdapter == NULL)
	{
		return;
	}

	SuCloseAdapter((SU_ADAPTER *)lpAdapter->hFile);

	if (lpAdapter->Filter != NULL)
	{
		SeFree(lpAdapter->Filter->bf_insns);
		SeFree(lpAdapter->Filter);
	}

	DeleteLock(lpAdapter->FilterLock);

	SeFree(lpAdapter);
}

bool CheckFilter(LPADAPTER a, UCHAR *buf, UINT size)
{
	bool ret = true;
	if (a == NULL || buf == NULL || size == 0)
	{
		return false;
	}

	Lock(a->FilterLock);
	{
		if (a->Filter != NULL)
		{
			UINT f = bpf_filter(a->Filter->bf_insns, buf, size, size);

			if (f == 0)
			{
				ret = false;
			}
		}
	}
	Unlock(a->FilterLock);

	return ret;
}

BOOLEAN PacketStartOem(PCHAR errorString, UINT errorStringLength)
{
	return false;
}

BOOLEAN PacketStartOemEx(PCHAR errorString, UINT errorStringLength, ULONG flags)
{
	return false;
}
