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

#define _WIN32_DCOM

#define	WIN32COM_CPP

#include <winsock2.h>
#include <windows.h>
#include <wincrypt.h>
#include <wininet.h>
#include <Wbemidl.h>
#include <comdef.h>
#include <Mshtmhst.h>
#include <shlobj.h>
#include <commctrl.h>
#include <Dbghelp.h>
#include <iphlpapi.h>
#include <Natupnp.h>
#include <devguid.h>
#include <regstr.h>
#include <cfgmgr32.h>
#include <tchar.h>
#include <objbase.h>
#include <Setupapi.h>
//#include "C:\WINDDK\7600.16385.0\inc\api\netcfgn.h"
#include "netcfgn.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
extern "C"
{
#include "..\Packet_dll\Se.h"
#include "..\Packet_dll\Ms.h"
#include "..\Packet_dll\Packet32.h"
#include "Installer.h"
#include "Win32Com.h"
}


bool InstallNdisProtocolDriver(char *inf_path, wchar_t *id, UINT lock_timeout)
{
	bool ret = false;
	HRESULT hr;
	INetCfg *pNetCfg;
	// Validate arguments
	if (inf_path == NULL || id == NULL)
	{
		return false;
	}
	hr = CoCreateInstance(CLSID_CNetCfg, NULL, CLSCTX_INPROC_SERVER, IID_INetCfg, (void **)&pNetCfg);

	if (SUCCEEDED(hr))
	{
		INetCfgLock *pLock;

		hr = pNetCfg->QueryInterface(IID_INetCfgLock, (PVOID*)&pLock);

		if (SUCCEEDED(hr))
		{
			LPWSTR locked_by;

			hr = pLock->AcquireWriteLock(lock_timeout, L"SoftEther VPN", &locked_by);

			if (SUCCEEDED(hr))
			{
				hr = pNetCfg->Initialize(NULL);

				if (SUCCEEDED(hr))
				{
					char inf_dir[MAX_PATH];

					SeGetDirNameFromFilePath(inf_dir, sizeof(inf_dir), inf_path);

					if (SetupCopyOEMInfA(inf_path, inf_dir, SPOST_PATH, 0, NULL, 0, NULL, 0))
					{
						INetCfgClassSetup *pSetup;

						hr = pNetCfg->QueryNetCfgClass(&GUID_DEVCLASS_NETTRANS, IID_INetCfgClassSetup, (void **)&pSetup);

						if (SUCCEEDED(hr))
						{
							OBO_TOKEN token;
							INetCfgComponent *pComponent;

							SeZero(&token, sizeof(token));

							token.Type = OBO_USER;

							hr = pSetup->Install(id, &token, 0, 0, NULL, NULL, &pComponent);

							if (SUCCEEDED(hr))
							{
								pNetCfg->Apply();

								ret = true;
							}

							pSetup->Release();
						}

						if (ret == false)
						{
							char dst_inf_name[MAX_PATH];
							DWORD dst_inf_name_size = MAX_PATH;

							if (SetupCopyOEMInfA(inf_path, inf_dir, SPOST_PATH, SP_COPY_REPLACEONLY,
								dst_inf_name, dst_inf_name_size, &dst_inf_name_size, NULL) == false &&
								GetLastError() == ERROR_FILE_EXISTS)
							{
								SetupUninstallOEMInfA(dst_inf_name, 0, NULL);
							}
						}
					}
				}

				pLock->ReleaseWriteLock();
			}

			pLock->Release();
		}

		pNetCfg->Release();
	}

	return ret;
}

bool UninstallNdisProtocolDriver(wchar_t *id, UINT lock_timeout)
{
	bool ret = false;
	HRESULT hr;
	INetCfg *pNetCfg;
	// Validate arguments
	if (id == NULL)
	{
		return false;
	}
	hr = CoCreateInstance(CLSID_CNetCfg, NULL, CLSCTX_INPROC_SERVER, IID_INetCfg, (void **)&pNetCfg);

	if (SUCCEEDED(hr))
	{
		INetCfgLock *pLock;

		hr = pNetCfg->QueryInterface(IID_INetCfgLock, (PVOID*)&pLock);

		if (SUCCEEDED(hr))
		{
			LPWSTR locked_by;

			hr = pLock->AcquireWriteLock(lock_timeout, L"SoftEther VPN", &locked_by);

			if (SUCCEEDED(hr))
			{
				hr = pNetCfg->Initialize(NULL);

				if (SUCCEEDED(hr))
				{
					INetCfgComponent *pComponent;
					hr = pNetCfg->FindComponent(id, &pComponent);

					if (SUCCEEDED(hr))
					{
						INetCfgClassSetup *pSetup;

						hr = pNetCfg->QueryNetCfgClass(&GUID_DEVCLASS_NETTRANS, IID_INetCfgClassSetup, (void **)&pSetup);

						if (SUCCEEDED(hr))
						{
							OBO_TOKEN token;

							SeZero(&token, sizeof(token));

							token.Type = OBO_USER;

							hr = pSetup->DeInstall(pComponent, &token, NULL);

							if (SUCCEEDED(hr))
							{
								pNetCfg->Apply();

								ret = true;
							}

							pSetup->Release();
						}
					}
				}

				pLock->ReleaseWriteLock();
			}

			pLock->Release();
		}

		pNetCfg->Release();
	}

	return ret;
}


