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
#include "..\Packet_dll\Se.h"
#include "..\Packet_dll\Ms.h"
#include "..\Packet_dll\Packet32.h"
#include "Win32Com.h"
#include "Installer.h"

UINT GetWindowsVersion()
{
	int osver = 0.0;
	UINT ret = OS_UNKNOWN;
	NTSTATUS(WINAPI * RtlGetVersion)(LPOSVERSIONINFOEXW);

	OSVERSIONINFOEXW osInfo;
	*(FARPROC*)&RtlGetVersion = GetProcAddress(GetModuleHandleA("ntdll"), "RtlGetVersion");

	if (NULL != RtlGetVersion)
	{
		osInfo.dwOSVersionInfoSize = sizeof(osInfo);
		RtlGetVersion(&osInfo);
		osver = osInfo.dwMajorVersion;

		if (osver == 7)
		{
			ret = OS_WIN7;
		}

		else if (osver == 8)
		{
			ret = OS_WIN8;
		}

		else if (osver == 10)
		{
			ret = OS_WIN10;
		}
		else if (osver == 11)
		{
			ret = OS_WIN11;
		}
	}

	return ret;
}

bool UninstallDllFromSystem32(char *dst_filename)
{
	char system32[MAX_PATH];
	char dst_fullpath[MAX_PATH];
	char bak_fullpath[MAX_PATH];
	bool ret;

	if (Is64BitCode() || IsWow64() == false)
	{
		GetSystemDirectoryA(system32, sizeof(system32));
	}
	else
	{
		GetSystemWow64DirectoryA(system32, sizeof(system32));
	}

	SeStrCpy(dst_fullpath, sizeof(dst_fullpath), system32);
	SeStrCat(dst_fullpath, sizeof(dst_fullpath), "\\");
	SeStrCat(dst_fullpath, sizeof(dst_fullpath), dst_filename);

	SeStrCpy(bak_fullpath, sizeof(bak_fullpath), dst_fullpath);
	SeStrCat(bak_fullpath, sizeof(bak_fullpath), ".bak");

LABEL_RETRY:
	ret = DeleteFileA(dst_fullpath);
	if (ret == false)
	{
		char tmp[MAX_SIZE];

		wsprintfA(tmp,
			"Deleting the file \"%s\" failed.\r\n\r\n"
			"Make sure that there are no running programs using WinPcap DLL.",
			dst_fullpath);

		if (MessageBoxA(NULL, tmp, INSTALLER_TITLE, MB_ICONEXCLAMATION | MB_SYSTEMMODAL | MB_RETRYCANCEL) == IDRETRY)
		{
			goto LABEL_RETRY;
		}
		return false;
	}

	MoveFileA(bak_fullpath, dst_fullpath);

	return true;
}

bool InstallDllToSystem32(char *src_dirname, char *src_filename, char *dst_filename)
{
	char system32[MAX_PATH];
	char src_fullpath[MAX_PATH];
	char dst_fullpath[MAX_PATH];

	SeStrCpy(src_fullpath, sizeof(src_fullpath), src_dirname);
	SeStrCat(src_fullpath, sizeof(src_fullpath), "\\");
	SeStrCat(src_fullpath, sizeof(src_fullpath), src_filename);

	if (Is64BitCode() || IsWow64() == false)
	{
		GetSystemDirectoryA(system32, sizeof(system32));
	}
	else
	{
		GetSystemWow64DirectoryA(system32, sizeof(system32));
	}

	SeStrCpy(dst_fullpath, sizeof(dst_fullpath), system32);
	SeStrCat(dst_fullpath, sizeof(dst_fullpath), "\\");
	SeStrCat(dst_fullpath, sizeof(dst_fullpath), dst_filename);

	if (IsWin10PcapFile(dst_fullpath) == false)
	{
		char dst_backup[MAX_PATH];
		SeStrCpy(dst_backup, sizeof(dst_backup), dst_fullpath);
		SeStrCat(dst_backup, sizeof(dst_backup), ".bak");

		CopyFileA(dst_fullpath, dst_backup, false);
	}

LABEL_RETRY:
	if (CopyFileA(src_fullpath, dst_fullpath, false) == false)
	{
		char tmp[MAX_SIZE];

		wsprintfA(tmp,
			"The installation of the DLL file to the path \"%s\" failed.\r\n\r\n"
			"Make sure that there are no running programs using WinPcap DLL.",
			dst_fullpath);

		if (MessageBoxA(NULL, tmp, INSTALLER_TITLE, MB_ICONEXCLAMATION | MB_SYSTEMMODAL | MB_RETRYCANCEL) == IDRETRY)
		{
			goto LABEL_RETRY;
		}

		return false;
	}

	return true;
}

bool IsWin10PcapFile(char *filename)
{
	char tmp[1024];
	if (filename == NULL)
	{
		return false;
	}

	SeZero(tmp, sizeof(tmp));
	MsGetFileVersion(filename, tmp, sizeof(tmp));

	if (SeStartWith(tmp, "10,"))
	{
		return true;
	}

	return false;
}

int PASCAL WinMain(HINSTANCE hInst, HINSTANCE hPrev, char *CmdLine, int CmdShow)
{
	bool uninstall_mode = false;
	char exe_name[MAX_PATH];
	char exe_dir[MAX_PATH];
	UINT os_ver = GetWindowsVersion();

	CoInitialize(NULL);

	DisableWow64FsRedirection();

	if (SeStartWith(CmdLine, "/uninstall"))
	{
		uninstall_mode = true;
	}

	GetModuleFileNameA(hInst, exe_name, sizeof(exe_name));
	SeGetDirNameFromFilePath(exe_dir, sizeof(exe_dir), exe_name);

	if (uninstall_mode == false)
	{
		char driver_inf_filename[MAX_PATH] = {0};
		bool install_driver = false;

		// Check the Windows version
		if (os_ver == OS_UNKNOWN)
		{
			MessageBoxA(NULL, "This operating system is not supported by Win10Pcap.\r\n\r\n"
				"Win10Pcap requires Windows 7, Server 2008 R2, Windows 8, Windows 8.1, Windows Server 2012, Windows Server 2012 R2 or Windows 10.",
				INSTALLER_TITLE,
				MB_ICONSTOP | MB_SYSTEMMODAL);
			return -1;
		}

		SeStrCpy(driver_inf_filename, sizeof(driver_inf_filename), exe_dir);
		if (os_ver == OS_WIN11)
		{
			SeStrCat(driver_inf_filename, sizeof(driver_inf_filename), "\\drivers\\win11");
		}
		if (os_ver == OS_WIN10)
		{
			SeStrCat(driver_inf_filename, sizeof(driver_inf_filename), "\\drivers\\win10");
		}
		else
		{
			SeStrCat(driver_inf_filename, sizeof(driver_inf_filename), "\\drivers\\win78");
		}
		SeStrCat(driver_inf_filename, sizeof(driver_inf_filename), "\\Win10Pcap.inf");

		// Install the device driver
		if (Is64BitCode())
		{
			// x64
			install_driver = true;
		}
		else if (IsWow64() == false)
		{
			// x86
			install_driver = true;
		}
		else
		{
			// Do nothing.
		}

		if (install_driver)
		{
LABEL_RETRY_INSTALL_DRIVER:

			if (InstallNdisProtocolDriver(driver_inf_filename, L"Win10Pcap", 60 * 1000) == false)
			{
				if (MessageBoxA(NULL, "The install process of the Win10Pcap NDIS device driver failed.", 
					INSTALLER_TITLE,
					MB_ICONEXCLAMATION | MB_SYSTEMMODAL | MB_RETRYCANCEL) == IDRETRY)
				{
					goto LABEL_RETRY_INSTALL_DRIVER;
				}
				else
				{
					return -1;
				}
			}

			MsStartService("Win10Pcap");
		}

		if (InstallDllToSystem32(exe_dir, "Packet.dll", "Packet.dll") == false ||
			InstallDllToSystem32(exe_dir, "wpcap.dll", "wpcap.dll") == false)
		{
			return -1;
		}

		if (Is64BitCode() == false && Is64BitWindows())
		{
			// Run x64
			char x64_exe[MAX_PATH];

			wsprintfA(x64_exe, "%s\\..\\x64\\Installer.exe", exe_dir);

			Win32RunAndWaitProcess(x64_exe, CmdLine, false, false, INFINITE);
		}
	}
	else
	{
		bool uninstall_driver = false;

		UninstallDllFromSystem32("Packet.dll");
		UninstallDllFromSystem32("wpcap.dll");

		// Install the device driver
		if (Is64BitCode())
		{
			// x64
			uninstall_driver = true;
		}
		else if (IsWow64() == false)
		{
			// x86
			uninstall_driver = true;
		}
		else
		{
			// Do nothing.
		}

		if (uninstall_driver)
		{
LABEL_RETRY_UNINSTALL_DRIVER:
			if (UninstallNdisProtocolDriver(L"Win10Pcap", 60 * 1000) == false)
			{
				if (MessageBoxA(NULL, "The uninstall process of the Win10Pcap NDIS device driver failed.", 
					INSTALLER_TITLE,
					MB_ICONEXCLAMATION | MB_SYSTEMMODAL | MB_RETRYCANCEL) == IDRETRY)
				{
					goto LABEL_RETRY_UNINSTALL_DRIVER;
				}
			}
		}

		if (Is64BitCode() == false && Is64BitWindows())
		{
			// Run x64
			char x64_exe[MAX_PATH];

			wsprintfA(x64_exe, "%s\\..\\x64\\Installer.exe", exe_dir);

			Win32RunAndWaitProcess(x64_exe, CmdLine, false, false, INFINITE);
		}
	}

	CoUninitialize();

	return 0;
}

