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

#define	_CRT_SECURE_NO_WARNINGS

#define SE_INTERNAL
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

// Get the directory name from the file path
void SeGetDirNameFromFilePath(char *dst, UINT size, char *filepath)
{
	char tmp[MAX_SIZE];
	UINT wp;
	UINT i;
	UINT len;
	// Validate arguments
	if (dst == NULL || filepath == NULL)
	{
		return;
	}

	SeStrCpy(tmp, sizeof(tmp), filepath);
	if (SeEndWith(tmp, "\\") || SeEndWith(tmp, "/"))
	{
		tmp[SeStrLen(tmp) - 1] = 0;
	}

	len = SeStrLen(tmp);

	SeStrCpy(dst, size, "");

	wp = 0;

	for (i = 0;i < len;i++)
	{
		char c = tmp[i];
		if (c == '/' || c == '\\')
		{
			tmp[wp++] = 0;
			wp = 0;
			SeStrCat(dst, size, tmp);
			tmp[wp++] = c;
		}
		else
		{
			tmp[wp++] = c;
		}
	}

	if (SeStrLen(dst) == 0)
	{
		SeStrCpy(dst, size, "\\");
	}
}

// Unicode string copy
wchar_t *SeUniCopyStr(wchar_t *str)
{
	return SeCopyUniStr(str);
}
// Copy the Unicode string
wchar_t *SeCopyUniStr(wchar_t *str)
{
	UINT len;
	wchar_t *dst;
	// Validate arguments
	if (str == NULL)
	{
		return NULL;
	}

	len = SeUniStrLen(str);
	dst = SeMalloc((len + 1) * sizeof(wchar_t));
	SeUniStrCpy(dst, 0, str);

	return dst;
}


// Compare the strings in case-insensitive mode
int SeUniStrCmpi(wchar_t *str1, wchar_t *str2)
{
	UINT i;
	// Validate arguments
	if (str1 == NULL && str2 == NULL)
	{
		return 0;
	}
	if (str1 == NULL)
	{
		return 1;
	}
	if (str2 == NULL)
	{
		return -1;
	}

	// String comparison
	i = 0;
	while (true)
	{
		wchar_t c1, c2;
		c1 = SeUniToUpper(str1[i]);
		c2 = SeUniToUpper(str2[i]);
		if (c1 > c2)
		{
			return 1;
		}
		else if (c1 < c2)
		{
			return -1;
		}
		if (str1[i] == 0 || str2[i] == 0)
		{
			return 0;
		}
		i++;
	}
}

// Compare the string
int SeUniStrCmp(wchar_t *str1, wchar_t *str2)
{
	// Validate arguments
	if (str1 == NULL && str2 == NULL)
	{
		return 0;
	}
	if (str1 == NULL)
	{
		return 1;
	}
	if (str2 == NULL)
	{
		return -1;
	}

	return wcscmp(str1, str2);
}

// Uncapitalize the string
void SeUniStrLower(wchar_t *str)
{
	UINT i, len;
	// Validate arguments
	if (str == NULL)
	{
		return;
	}

	len = SeUniStrLen(str);
	for (i = 0;i < len;i++)
	{
		str[i] = SeUniToLower(str[i]);
	}
}

// Capitalize the string
void SeUniStrUpper(wchar_t *str)
{
	UINT i, len;
	// Validate arguments
	if (str == NULL)
	{
		return;
	}

	len = SeUniStrLen(str);
	for (i = 0;i < len;i++)
	{
		str[i] = SeUniToUpper(str[i]);
	}
}

// Uncapitalize a character
wchar_t SeUniToLower(wchar_t c)
{
	if (c >= L'A' && c <= L'Z')
	{
		c += L'a' - L'A';
	}

	return c;
}

// Capitalize a character
wchar_t SeUniToUpper(wchar_t c)
{
	if (c >= L'a' && c <= L'z')
	{
		c -= L'a' - L'A';
	}

	return c;
}

// String concatenation
UINT SeUniStrCat(wchar_t *dst, UINT size, wchar_t *src)
{
	UINT len1, len2, len_test;
	// Validate arguments
	if (dst == NULL || src == NULL)
	{
		return 0;
	}
	if (size != 0 && size < sizeof(wchar_t))
	{
		return 0;
	}
	if (size == sizeof(wchar_t))
	{
		wcscpy(dst, L"");
		return 0;
	}
	if (size == 0)
	{
		// Ignore the length
		size = 0x3fffffff;
	}

	len1 = SeUniStrLen(dst);
	len2 = SeUniStrLen(src);
	len_test = len1 + len2 + 1;
	if (len_test > (size / sizeof(wchar_t)))
	{
		if (len2 <= (len_test - (size / sizeof(wchar_t))))
		{
			return 0;
		}
		len2 -= len_test - (size / sizeof(wchar_t));
	}
	SeCopy(&dst[len1], src, len2 * sizeof(wchar_t));
	dst[len1 + len2] = 0;

	return len1 + len2;
}
UINT SeUniStrCatLeft(wchar_t *dst, UINT size, wchar_t *src)
{
	wchar_t *s;
	// Validate arguments
	if (dst == NULL || src == NULL)
	{
		return 0;
	}

	s = SeUniCopyStr(dst);
	SeUniStrCpy(dst, size, s);
	SeUniStrCat(dst, size, src);
	SeFree(s);

	return SeUniStrLen(dst);
}

// Convert Unicode string to ANSI string
UINT SeUniToStr(char *str, UINT size, wchar_t *s)
{
	UINT ret;
	char *tmp;
	UINT new_size;
	// Validate arguments
	if (s == NULL || str == NULL)
	{
		return 0;
	}

	new_size = SeCalcUniToStr(s);
	if (new_size == 0)
	{
		if (size >= 1)
		{
			SeStrCpy(str, 0, "");
		}
		return 0;
	}
	tmp = SeMalloc(new_size);
	tmp[0] = 0;
	wcstombs(tmp, s, new_size);
	tmp[new_size - 1] = 0;
	ret = SeStrCpy(str, size, tmp);
	SeFree(tmp);

	return ret;
}

// Get the required number of bytes to convert Unicode string to the ANSI string
UINT SeCalcUniToStr(wchar_t *s)
{
	UINT ret;
	// Validate arguments
	if (s == NULL)
	{
		return 0;
	}

	ret = (UINT)wcstombs(NULL, s, SeUniStrLen(s));
	if (ret == (UINT)-1)
	{
		return 0;
	}

	return ret + 1;
}

// Get the length of the string
UINT SeUniStrLen(wchar_t *str)
{
	UINT i;
	// Validate arguments
	if (str == NULL)
	{
		return 0;
	}

	i = 0;
	while (true)
	{
		if (str[i] == 0)
		{
			break;
		}
		i++;
	}

	return i;
}

// String copy
UINT SeUniStrCpy(wchar_t *dst, UINT size, wchar_t *src)
{
	UINT len;
	// Validate arguments
	if (dst == NULL || src == NULL)
	{
		if (src == NULL && dst != NULL)
		{
			if (size >= sizeof(wchar_t))
			{
				dst[0] = L'\0';
			}
		}
		return 0;
	}
	if (dst == src)
	{
		return SeUniStrLen(src);
	}
	if (size != 0 && size < sizeof(wchar_t))
	{
		return 0;
	}
	if (size == sizeof(wchar_t))
	{
		wcscpy(dst, L"");
		return 0;
	}
	if (size == 0)
	{
		// Ignore the length
		size = 0x3fffffff;
	}

	// Check the length
	len = SeUniStrLen(src);
	if (len <= (size / sizeof(wchar_t) - 1))
	{
		SeCopy(dst, src, (len + 1) * sizeof(wchar_t));
	}
	else
	{
		len = size / sizeof(wchar_t) - 1;
		SeCopy(dst, src, len * sizeof(wchar_t));
		dst[len] = 0;
	}

	return len;
}

// Converted an ANSI string to a Unicode string
UINT SeStrToUni(wchar_t *s, UINT size, char *str)
{
	UINT ret;
	wchar_t *tmp;
	UINT new_size;
	// Validate arguments
	if (s == NULL || str == NULL)
	{
		return 0;
	}

	new_size = SeCalcStrToUni(str);
	if (new_size == 0)
	{
		if (size >= 2)
		{
			SeUniStrCpy(s, 0, L"");
		}
		return 0;
	}
	tmp = SeMalloc(new_size);
	tmp[0] = 0;
	mbstowcs(tmp, str, SeStrLen(str));
	tmp[(new_size - 1) / sizeof(wchar_t)] = 0;
	ret = SeUniStrCpy(s, size, tmp);
	SeFree(tmp);

	return ret;
}

// Get the required buffer size for converting an ANSI string to an Unicode string
UINT SeCalcStrToUni(char *str)
{
	UINT ret;
	// Validate arguments
	if (str == NULL)
	{
		return 0;
	}

	ret = (UINT)mbstowcs(NULL, str, SeStrLen(str));
	if (ret == (UINT)-1)
	{
		return 0;
	}

	return (ret + 1) * sizeof(wchar_t);
}

char *SeReadNextLine(SE_BUF *b)
{
	char *tmp;
	char *buf;
	UINT len;
	if (b == NULL)
	{
		return NULL;
	}

	tmp = (char *)b->Buf + b->Current;
	if ((b->Size - b->Current) == 0)
	{
		return NULL;
	}
	len = 0;
	while (true)
	{
		if (tmp[len] == 13 || tmp[len] == 10)
		{
			if (tmp[len] == 13)
			{
				if (len < (b->Size - b->Current))
				{
					len++;
				}
			}
			break;
		}
		len++;
		if (len >= (b->Size - b->Current))
		{
			break;
		}
	}

	buf = SeZeroMalloc(len + 1);
	SeReadBuf(b, buf, len);
	SeSeekBuf(b, 1, 1);

	if (SeStrLen(buf) >= 1)
	{
		if (buf[SeStrLen(buf) - 1] == 13)
		{
			buf[SeStrLen(buf) - 1] = 0;
		}
	}

	return buf;
}

void SeMacToStr(char *str, UINT str_size, UCHAR *mac_address)
{
	if (str == NULL || mac_address == NULL)
	{
		if (str != NULL)
		{
			str[0] = '\0';
		}
		return;
	}

	SeFormat(str, str_size, "%02X-%02X-%02X-%02X-%02X-%02X",
		mac_address[0],
		mac_address[1],
		mac_address[2],
		mac_address[3],
		mac_address[4],
		mac_address[5]);
}

bool SeStrToMac(UCHAR *mac_address, char *str)
{
	return SeStrToBinEx(mac_address, 6, str);
}

SE_BUF *SeStrToBin(char *str)
{
	SE_BUF *b;
	UINT len, i;
	char tmp[3];
	if (str == NULL)
	{
		return NULL;
	}

	len = SeStrLen(str);
	tmp[0] = 0;
	b = SeNewBuf();
	for (i = 0;i < len;i++)
	{
		char c = str[i];
		c = SeToUpper(c);
		if (('0' <= c && c <= '9') || ('A' <= c && c <= 'F'))
		{
			if (tmp[0] == 0)
			{
				tmp[0] = c;
				tmp[1] = 0;
			}
			else if (tmp[1] == 0)
			{
				UCHAR data;
				char tmp2[64];
				tmp[1] = c;
				tmp[2] = 0;
				SeStrCpy(tmp2, sizeof(tmp2), tmp);
				data = SeHexToInt(tmp2);
				SeWriteBuf(b, &data, 1);
				SeZero(tmp, sizeof(tmp));	
			}
		}
		else if (c == ' ' || c == ',' || c == '-' || c == ':')
		{
		}
		else
		{
			break;
		}
	}

	return b;
}
bool SeStrToBinEx(void *dst, UINT dst_size, char *str)
{
	SE_BUF *b;
	bool ret = false;
	if (dst == NULL)
	{
		return false;
	}
	if (str == NULL)
	{
		str = "";
	}

	b = SeStrToBin(str);

	if (dst_size == b->Size)
	{
		ret = true;
		SeCopy(dst, b->Buf, dst_size);
	}

	SeFreeBuf(b);

	return ret;
}

void SeBinToStrEx(char *str, UINT str_size, void *data, UINT data_size)
{
	char *tmp;
	UCHAR *buf = (UCHAR *)data;
	UINT size;
	UINT i;
	if (str == NULL || data == NULL)
	{
		return;
	}

	size = data_size * 3 * sizeof(char) + 1;
	tmp = SeZeroMalloc(size);
	for (i = 0;i < data_size;i++)
	{
		SeFormat(&tmp[i * 3], 0, "%02X ", buf[i]);
	}
	SeTrim(tmp);
	SeStrCpy(str, str_size, tmp);
	SeFree(tmp);
}
void SeBinToStr(char *str, UINT str_size, void *data, UINT data_size)
{
	char *tmp;
	UCHAR *buf = (UCHAR *)data;
	UINT size;
	UINT i;
	// 引数チェック
	if (str == NULL || data == NULL)
	{
		return;
	}

	size = data_size * 2 * sizeof(char) + 1;
	tmp = SeZeroMalloc(size);
	for (i = 0;i < data_size;i++)
	{
		SeFormat(&tmp[i * 2], 0, "%02X", buf[i]);
	}
	SeTrim(tmp);
	SeStrCpy(str, str_size, tmp);
	SeFree(tmp);
}

char *SeFormatEx(char *fmt, void **arg_list)
{
	UINT i, len;
	char *tmp;
	UINT tmp_size;
	SE_LIST *o;
	UINT mode = 0;
	UINT wp;
	UINT total_size;
	char *ret;
	UINT n;
	// 引数チェック
	if (fmt == NULL)
	{
		return NULL;
	}

	len = SeStrLen(fmt);
	tmp_size = SeStrSize(fmt);
	tmp = SeMalloc(tmp_size);

	o = SeNewList(NULL);

	mode = 0;
	wp = 0;
	n = 0;

	for (i = 0;i < len;i++)
	{
		char c = fmt[i];

		if (mode == 0)
		{
			switch (c)
			{
			case '%':
				if (fmt[i + 1] == '%')
				{
					i++;
					tmp[wp++] = c;
				}
				else
				{
					mode = 1;
					tmp[wp++] = 0;
					wp = 0;
					SeInsert(o, SeCopyStr(tmp));
					tmp[wp++] = c;
				}
				break;

			default:
				tmp[wp++] = c;
				break;
			}
		}
		else
		{
			char *target_str;
			char *padding_str;
			bool left_padding;
			bool zero_padding;
			UINT target_str_len;
			UINT total_len;
			char *output_str;
			UINT padding;
			bool pointer_data;
			UINT value;
			UINT64 value64;
			void *pvalue;
			bool longlong_data;

			switch (c)
			{
			case 'c':
			case 'C':
			case 'd':
			case 'i':
			case 'u':
			case 'X':
			case 'x':
			case 's':
			case 'S':
				tmp[wp++] = c;
				tmp[wp++] = 0;
				pointer_data = false;
				longlong_data = false;
				value = 0;
				value64 = 0;
				pvalue = NULL;

				switch (c)
				{
				case 's':
				case 'S':
					pointer_data = true;
					break;
				}

				if ((SeStrLen(tmp) >= 5 && tmp[SeStrLen(tmp) - 4] == 'I' &&
					tmp[SeStrLen(tmp) - 3] == '6' && tmp[SeStrLen(tmp) - 2] == '4') ||
					(SeStrLen(tmp) >= 4 && tmp[SeStrLen(tmp) - 3] == 'l' &&
					tmp[SeStrLen(tmp) - 2] == 'l'))
				{
					longlong_data = true;
				}

				pvalue = arg_list[n++];
				value = (UINT)pvalue;
				value64 = (UINT64)value;

				if (longlong_data)
				{
					void *pvalue2;
					pvalue2 = arg_list[n++];
					value64 = value64 + (UINT64)(UINT)pvalue2 * 4294967296ULL;
				}

				switch (c)
				{
				case 's':
				case 'S':
					if (pvalue == NULL)
					{
						target_str = SeCopyStr("(null)");
					}
					else
					{
						target_str = SeCopyStr(pvalue);
					}
					break;

				case 'u':
				case 'U':
				case 'i':
				case 'I':
				case 'd':
				case 'D':
					if (longlong_data == false)
					{
						target_str = SeZeroMalloc(12);
						SeToStr(target_str, value);
					}
					else
					{
						target_str = SeZeroMalloc(24);
						SeToStr64(target_str, value64);
					}
					break;

				case 'x':
				case 'X':
					target_str = SeZeroMalloc(20);
					SeToHex(target_str, value);

					if (c == 'X')
					{
						SeStrUpper(target_str);
					}
					break;
				}

				padding = 0;
				zero_padding = false;
				left_padding = false;

				if (tmp[1] == '-')
				{
					if (SeStrLen(tmp) >= 3)
					{
						if (tmp[2] == '0')
						{
							zero_padding = true;
							padding = SeToInt(&tmp[3]);
						}
						else
						{
							padding = SeToInt(&tmp[2]);
						}
					}
					left_padding = true;
				}
				else
				{
					if (SeStrLen(tmp) >= 2)
					{
						if (tmp[1] == '0')
						{
							zero_padding = true;
							padding = SeToInt(&tmp[2]);
						}
						else
						{
							padding = SeToInt(&tmp[1]);
						}
					}
				}

				target_str_len = SeStrLen(target_str);

				if (padding > target_str_len)
				{
					UINT len = padding - target_str_len;

					padding_str = SeMakeCharArray((zero_padding ? '0' : ' '), len);
				}
				else
				{
					padding_str = SeZeroMalloc(sizeof(char));
				}

				total_len = sizeof(char) * (SeStrLen(padding_str) + SeStrLen(target_str) + 1);
				output_str = SeZeroMalloc(total_len);
				output_str[0] = 0;

				if (left_padding == false)
				{
					SeStrCat(output_str, total_len, padding_str);
				}
				SeStrCat(output_str, total_len, target_str);
				if (left_padding)
				{
					SeStrCat(output_str, total_len, padding_str);
				}

				SeAdd(o, output_str);

				SeFree(target_str);
				SeFree(padding_str);

				wp = 0;
				mode = 0;
				break;

			default:
				tmp[wp++] = c;
				break;
			}
		}
	}
	tmp[wp++] = 0;
	wp = 0;

	if (SeStrLen(tmp) >= 1)
	{
		SeAdd(o, SeCopyStr(tmp));
	}

	total_size = sizeof(char);
	for (i = 0;i < SE_LIST_NUM(o);i++)
	{
		char *s = SE_LIST_DATA(o, i);
		total_size += SeStrLen(s) * sizeof(char);
	}

	ret = SeZeroMalloc(total_size);
	for (i = 0;i < SE_LIST_NUM(o);i++)
	{
		char *s = SE_LIST_DATA(o, i);
		SeStrCat(ret, total_size, s);
		SeFree(s);
	}

	SeFreeList(o);

	SeFree(tmp);

	return ret;
}

void SeFormatArgs(char *buf, UINT size, char *fmt, void **args)
{
	char *ret;
	if (buf == NULL || fmt == NULL)
	{
		return;
	}
	if (size == 1)
	{
		buf[0] = 0;
		return;
	}

	ret = SeFormatEx(fmt, args);

	SeStrCpy(buf, size, ret);

	SeFree(ret);
}
void SeFormat(char *buf, UINT size, char *fmt, ...)
{
	SeFormatArgs(buf, size, fmt, SE_BUILD_ARGLIST(fmt));
}

char *SeMakeCharArray(char c, UINT count)
{
	UINT i;
	char *ret = SeMalloc(count + 1);

	for (i = 0;i < count;i++)
	{
		ret[i] = c;
	}

	ret[count] = 0;

	return ret;
}

bool SeIsAllLowerStr(char *str)
{
	UINT i, len;
	if (str == NULL)
	{
		return false;
	}

	len = SeStrLen(str);

	for (i = 0;i < len;i++)
	{
		char c = str[i];

		if ((c >= '0' && c <= '9') ||
			(c >= 'a' && c <= 'z'))
		{
		}
		else
		{
			return false;
		}
	}

	return true;
}

bool SeIsAllUpperStr(char *str)
{
	UINT i, len;
	if (str == NULL)
	{
		return false;
	}

	len = SeStrLen(str);

	for (i = 0;i < len;i++)
	{
		char c = str[i];

		if ((c >= '0' && c <= '9') ||
			(c >= 'A' && c <= 'Z'))
		{
		}
		else
		{
			return false;
		}
	}

	return true;
}

SE_TOKEN_LIST *SeUniqueToken(SE_TOKEN_LIST *t)
{
	UINT i, num, j, n;
	SE_TOKEN_LIST *ret;
	if (t == NULL)
	{
		return NULL;
	}

	num = 0;
	for (i = 0;i < t->NumTokens;i++)
	{
		bool exists = false;

		for (j = 0;j < i;j++)
		{
			if (SeStrCmpi(t->Token[j], t->Token[i]) == 0)
			{
				exists = true;
				break;
			}
		}

		if (exists == false)
		{
			num++;
		}
	}

	ret = SeZeroMalloc(sizeof(SE_TOKEN_LIST));
	ret->Token = SeZeroMalloc(sizeof(char *) * num);
	ret->NumTokens = num;

	n = 0;

	for (i = 0;i < t->NumTokens;i++)
	{
		bool exists = false;

		for (j = 0;j < i;j++)
		{
			if (SeStrCmpi(t->Token[j], t->Token[i]) == 0)
			{
				exists = true;
				break;
			}
		}

		if (exists == false)
		{
			ret->Token[n++] = SeCopyStr(t->Token[i]);
		}
	}

	return ret;
}

void SeToStr3(char *str, UINT size, UINT64 v)
{
	char tmp[128];
	char tmp2[128];
	UINT i, len, wp;
	if (str == NULL)
	{
		return;
	}

	SeToStr64(tmp, v);

	wp = 0;
	len = SeStrLen(tmp);

	for (i = len - 1;((int)i) >= 0;i--)
	{
		tmp2[wp++] = tmp[i];
	}
	tmp2[wp++] = 0;

	wp = 0;

	for (i = 0;i < len;i++)
	{
		if (i != 0 && (i % 3) == 0)
		{
			tmp[wp++] = ',';
		}
		tmp[wp++] = tmp2[i];
	}
	tmp[wp++] = 0;
	wp = 0;
	len = SeStrLen(tmp);

	for (i = len - 1;((int)i) >= 0;i--)
	{
		tmp2[wp++] = tmp[i];
	}
	tmp2[wp++] = 0;

	SeStrCpy(str, size, tmp2);
}

void SeFreeToken(SE_TOKEN_LIST *t)
{
	UINT i;
	if (t == NULL)
	{
		return;
	}

	for (i = 0;i < t->NumTokens;i++)
	{
		if (t->Token[i] != 0)
		{
			SeFree(t->Token[i]);
		}
	}
	SeFree(t->Token);
	SeFree(t);
}

SE_TOKEN_LIST *SeParseTokenWithNullStr(char *str, char *split_chars)
{
	SE_LIST *o;
	UINT i, len;
	SE_BUF *b;
	char zero = 0;
	SE_TOKEN_LIST *t;
	if (str == NULL)
	{
		return SeNullTokenList();
	}
	if (split_chars == NULL)
	{
		split_chars = SeDefaultTokenSplitChars();
	}

	b = SeNewBuf();
	o = SeNewList(NULL);

	len = SeStrLen(str);

	for (i = 0;i < (len + 1);i++)
	{
		char c = str[i];
		bool flag = SeIsCharInStr(split_chars, c);

		if (c == '\0')
		{
			flag = true;
		}

		if (flag == false)
		{
			SeWriteBuf(b, &c, sizeof(char));
		}
		else
		{
			SeWriteBuf(b, &zero, sizeof(char));

			SeInsert(o, SeCopyStr((char *)b->Buf));
			SeClearBuf(b);
		}
	}

	t = SeZeroMalloc(sizeof(SE_TOKEN_LIST));
	t->NumTokens = SE_LIST_NUM(o);
	t->Token = SeZeroMalloc(sizeof(char *) * t->NumTokens);

	for (i = 0;i < t->NumTokens;i++)
	{
		t->Token[i] = SE_LIST_DATA(o, i);
	}

	SeFreeList(o);
	SeFreeBuf(b);

	return t;
}

SE_TOKEN_LIST *SeParseToken(char *str, char *split_chars)
{
	SE_LIST *o;
	UINT i, len;
	bool last_flag;
	SE_BUF *b;
	char zero = 0;
	SE_TOKEN_LIST *t;
	if (str == NULL)
	{
		return SeNullTokenList();
	}
	if (split_chars == NULL)
	{
		split_chars = SeDefaultTokenSplitChars();
	}

	b = SeNewBuf();
	o = SeNewList(NULL);

	len = SeStrLen(str);
	last_flag = false;

	for (i = 0;i < (len + 1);i++)
	{
		char c = str[i];
		bool flag = SeIsCharInStr(split_chars, c);

		if (c == '\0')
		{
			flag = true;
		}

		if (flag == false)
		{
			SeWriteBuf(b, &c, sizeof(char));
		}
		else
		{
			if (last_flag == false)
			{
				SeWriteBuf(b, &zero, sizeof(char));

				if ((SeStrLen((char *)b->Buf)) != 0)
				{
					SeInsert(o, SeCopyStr((char *)b->Buf));
				}
				SeClearBuf(b);
			}
		}

		last_flag = flag;
	}

	t = SeZeroMalloc(sizeof(SE_TOKEN_LIST));
	t->NumTokens = SE_LIST_NUM(o);
	t->Token = SeZeroMalloc(sizeof(char *) * t->NumTokens);

	for (i = 0;i < t->NumTokens;i++)
	{
		t->Token[i] = SE_LIST_DATA(o, i);
	}

	SeFreeList(o);
	SeFreeBuf(b);

	return t;
}

bool SeIsCharInStr(char *str, char c)
{
	UINT i, len;
	if (str == NULL)
	{
		return false;
	}

	len = SeStrLen(str);
	for (i = 0;i < len;i++)
	{
		if (str[i] == c)
		{
			return true;
		}
	}

	return false;
}

SE_TOKEN_LIST *SeNullTokenList()
{
	SE_TOKEN_LIST *t = SeZeroMalloc(sizeof(SE_TOKEN_LIST));

	t->NumTokens = 0;
	t->Token = SeZeroMalloc(0);

	return t;
}

char *SeDefaultTokenSplitChars()
{
	return " ,\t\r\n";
}

char *SeNormalizeCrlf(char *str)
{
	char *ret;
	UINT ret_size, i, len, wp;
	if (str == NULL)
	{
		return NULL;
	}

	len = SeStrLen(str);
	ret_size = sizeof(char) * (len + 32) * 2;
	ret = SeMalloc(ret_size);

	wp = 0;

	for (i = 0;i < len;i++)
	{
		char c = str[i];

		switch (c)
		{
		case '\r':
			if (str[i + 1] == '\n')
			{
				i++;
			}
			ret[wp++] = '\r';
			ret[wp++] = '\n';
			break;

		case '\n':
			ret[wp++] = '\r';
			ret[wp++] = '\n';
			break;

		default:
			ret[wp++] = c;
			break;
		}
	}

	ret[wp++] = 0;

	return ret;
}

bool SeIsEmptyStr(char *str)
{
	char *s;
	if (str == NULL)
	{
		return true;
	}

	s = SeTrimCopy(str);

	if (SeStrLen(s) == 0)
	{
		SeFree(s);
		return true;
	}
	else
	{
		SeFree(s);
		return false;
	}
}

bool SeEndWith(char *str, char *key)
{
	UINT str_len;
	UINT key_len;
	if (str == NULL || key == NULL)
	{
		return false;
	}

	str_len = SeStrLen(str);
	key_len = SeStrLen(key);
	if (str_len < key_len)
	{
		return false;
	}

	if (SeStrCmpi(str + (str_len - key_len), key) == 0)
	{
		return true;
	}
	else
	{
		return false;
	}
}

bool SeStartWith(char *str, char *key)
{
	UINT str_len;
	UINT key_len;
	char *tmp;
	bool ret;
	if (str == NULL || key == NULL)
	{
		return false;
	}

	str_len = SeStrLen(str);
	key_len = SeStrLen(key);
	if (str_len < key_len)
	{
		return false;
	}
	if (str_len == 0 || key_len == 0)
	{
		return false;
	}
	tmp = SeCopyStr(str);
	tmp[key_len] = 0;

	if (SeStrCmpi(tmp, key) == 0)
	{
		ret = true;
	}
	else
	{
		ret = false;
	}

	SeFree(tmp);

	return ret;
}

void SeTrimCrlf(char *str)
{
	UINT len;
	if (str == NULL)
	{
		return;
	}
	len = SeStrLen(str);
	if (len == 0)
	{
		return;
	}

	if (str[len - 1] == '\n')
	{
		if (len >= 2 && str[len - 2] == '\n')
		{
			str[len - 2] = 0;
		}
		str[len - 1] = 0;
	}
	else if (str[len - 1] == '\r')
	{
		str[len - 1] = 0;
	}
}

UINT SeReplaceStri(char *dst, UINT size, char *string, char *old_keyword, char *new_keyword)
{
	return SeReplaceStrEx(dst, size, string, old_keyword, new_keyword, false);
}

UINT SeReplaceStr(char *dst, UINT size, char *string, char *old_keyword, char *new_keyword)
{
	return SeReplaceStrEx(dst, size, string, old_keyword, new_keyword, true);
}

UINT SeReplaceStrEx(char *dst, UINT size, char *string, char *old_keyword, char *new_keyword, bool case_sensitive)
{
	UINT i, j, num;
	UINT len_string, len_old, len_new;
	UINT len_ret;
	UINT wp;
	char *ret;
	if (string == NULL || old_keyword == NULL || new_keyword == NULL)
	{
		return 0;
	}

	len_string = SeStrLen(string);
	len_old = SeStrLen(old_keyword);
	len_new = SeStrLen(new_keyword);

	len_ret = SeCalcReplaceStrEx(string, old_keyword, new_keyword, case_sensitive);
	ret = SeMalloc(len_ret + 1);
	ret[len_ret] = '\0';

	i = 0;
	j = 0;
	num = 0;
	wp = 0;
	while (true)
	{
		i = SeSearchStrEx(string, old_keyword, i, case_sensitive);
		if (i == INFINITE)
		{
			SeCopy(ret + wp, string + j, len_string - j);
			wp += len_string - j;
			break;
		}
		num++;
		SeCopy(ret + wp, string + j, i - j);
		wp += i - j;
		SeCopy(ret + wp, new_keyword, len_new);
		wp += len_new;
		i += len_old;
		j = i;
	}

	SeStrCpy(dst, size, ret);

	SeFree(ret);

	return num;
}

UINT SeCalcReplaceStrEx(char *string, char *old_keyword, char *new_keyword, bool case_sensitive)
{
	UINT i, num;
	UINT len_string, len_old, len_new;
	if (string == NULL || old_keyword == NULL || new_keyword == NULL)
	{
		return 0;
	}

	len_string = SeStrLen(string);
	len_old = SeStrLen(old_keyword);
	len_new = SeStrLen(new_keyword);

	if (len_old == len_new)
	{
		return len_string;
	}

	num = 0;
	i = 0;
	while (true)
	{
		i = SeSearchStrEx(string, old_keyword, i, case_sensitive);
		if (i == INFINITE)
		{
			break;
		}
		i += len_old;
		num++;
	}

	return len_string + len_new * num - len_old * num;
}

UINT SeSearchStr(char *string, char *keyword, UINT start)
{
	return SeSearchStrEx(string, keyword, start, true);
}

UINT SeSearchStri(char *string, char *keyword, UINT start)
{
	return SeSearchStrEx(string, keyword, start, false);
}

UINT SeSearchStrEx(char *string, char *keyword, UINT start, bool case_sensitive)
{
	UINT len_string, len_keyword;
	UINT i;
	char *cmp_string, *cmp_keyword;
	bool found;
	if (string == NULL || keyword == NULL)
	{
		return INFINITE;
	}

	len_string = SeStrLen(string);
	if (len_string <= start)
	{
		return INFINITE;
	}

	len_keyword = SeStrLen(keyword);
	if (len_keyword == 0)
	{
		return INFINITE;
	}

	if ((len_string - start) < len_keyword)
	{
		return INFINITE;
	}

	if (case_sensitive)
	{
		cmp_string = string;
		cmp_keyword = keyword;
	}
	else
	{
		cmp_string = SeMalloc(len_string + 1);
		SeStrCpy(cmp_string, len_string + 1, string);
		cmp_keyword = SeMalloc(len_keyword + 1);
		SeStrCpy(cmp_keyword, len_keyword + 1, keyword);
		SeStrUpper(cmp_string);
		SeStrUpper(cmp_keyword);
	}

	found = false;
	for (i = start;i < (len_string - len_keyword + 1);i++)
	{
		if (!SeStrnCmp(&cmp_string[i], cmp_keyword, len_keyword))
		{
			found = true;
			break;
		}
	}

	if (case_sensitive == false)
	{
		SeFree(cmp_keyword);
		SeFree(cmp_string);
	}

	if (found == false)
	{
		return INFINITE;
	}
	return i;
}

char *SeCopyStr(char *str)
{
	UINT len;
	char *dst;
	if (str == NULL)
	{
		return NULL;
	}

	len = SeStrLen(str);
	dst = SeMalloc(len + 1);
	SeStrCpy(dst, len + 1, str);
	return dst;
}

char *SeTrimCopy(char *str)
{
	char *ret;
	if (str == NULL)
	{
		return NULL;
	}

	ret = SeCopyStr(str);
	SeTrim(ret);

	return ret;
}

void SeTrim(char *str)
{
	if (str == NULL)
	{
		return;
	}

	SeTrimLeft(str);

	SeTrimRight(str);
}

void SeTrimRight(char *str)
{
	char *buf, *tmp;
	UINT len, i, wp, wp2;
	bool flag;
	if (str == NULL)
	{
		return;
	}
	len = SeStrLen(str);
	if (len == 0)
	{
		return;
	}
	if (str[len - 1] != ' ' && str[len - 1] != '\t')
	{
		return;
	}

	buf = SeMalloc(len + 1);
	tmp = SeMalloc(len + 1);
	flag = false;
	wp = 0;
	wp2 = 0;
	for (i = 0;i < len;i++)
	{
		if (str[i] != ' ' && str[i] != '\t')
		{
			SeCopy(buf + wp, tmp, wp2);
			wp += wp2;
			wp2 = 0;
			buf[wp++] = str[i];
		}
		else
		{
			tmp[wp2++] = str[i];
		}
	}
	buf[wp] = 0;
	SeStrCpy(str, 0, buf);
	SeFree(buf);
	SeFree(tmp);
}

void SeTrimLeft(char *str)
{
	char *buf;
	UINT len, i, wp;
	bool flag;
	if (str == NULL)
	{
		return;
	}
	len = SeStrLen(str);
	if (len == 0)
	{
		return;
	}
	if (str[0] != ' ' && str[0] != '\t')
	{
		return;
	}

	buf = SeMalloc(len + 1);
	flag = false;
	wp = 0;
	for (i = 0;i < len;i++)
	{
		if (str[i] != ' ' && str[i] != '\t')
		{
			flag = TRUE;
		}
		if (flag)
		{
			buf[wp++] = str[i];
		}
	}
	buf[wp] = 0;
	SeStrCpy(str, 0, buf);
	SeFree(buf);
}

UINT64 SeHexToInt64(char *str)
{
	UINT len, i;
	UINT64 ret = 0;
	if (str == NULL)
	{
		return 0;
	}

	if (str[0] == '0' && (str[1] == 'x' || str[1] == 'X'))
	{
		str += 2;
	}

	len = SeStrLen(str);
	for (i = 0;i < len;i++)
	{
		char c = str[i];

		if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))
		{
			ret = ret * 16ULL + (UINT64)SeHexTo4Bit(c);
		}
		else
		{
			break;
		}
	}

	return ret;
}

UINT SeHexToInt(char *str)
{
	UINT len, i;
	UINT ret = 0;
	if (str == NULL)
	{
		return 0;
	}

	if (str[0] == '0' && (str[1] == 'x' || str[1] == 'X'))
	{
		str += 2;
	}

	len = SeStrLen(str);
	for (i = 0;i < len;i++)
	{
		char c = str[i];

		if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))
		{
			ret = ret * 16 + (UINT)SeHexTo4Bit(c);
		}
		else
		{
			break;
		}
	}

	return ret;
}

void SeToHex64(char *str, UINT64 value)
{
	char tmp[MAX_SIZE];
	UINT wp = 0;
	UINT len, i;
	if (str == NULL)
	{
		return;
	}

	SeStrCpy(tmp, 0, "");

	while (true)
	{
		UINT a = (UINT)(value % (UINT64)16);
		value = value / (UINT)16;
		tmp[wp++] = Se4BitToHex(a);
		if (value == 0)
		{
			tmp[wp++] = 0;
			break;
		}
	}

	len = SeStrLen(tmp);
	for (i = 0;i < len;i++)
	{
		str[len - i - 1] = tmp[i];
	}
	str[len] = 0;
}

void SeToHex(char *str, UINT value)
{
	char tmp[MAX_SIZE];
	UINT wp = 0;
	UINT len, i;
	if (str == NULL)
	{
		return;
	}

	SeStrCpy(tmp, 0, "");

	while (true)
	{
		UINT a = (UINT)(value % (UINT)16);
		value = value / (UINT)16;
		tmp[wp++] = Se4BitToHex(a);
		if (value == 0)
		{
			tmp[wp++] = 0;
			break;
		}
	}

	len = SeStrLen(tmp);
	for (i = 0;i < len;i++)
	{
		str[len - i - 1] = tmp[i];
	}
	str[len] = 0;
}

char Se4BitToHex(UINT value)
{
	value = value % 16;

	if (value <= 9)
	{
		return '0' + value;
	}
	else
	{
		return 'a' + (value - 10);
	}
}

UINT SeHexTo4Bit(char c)
{
	if ('0' <= c && c <= '9')
	{
		return c - '0';
	}
	else if ('a' <= c && c <= 'f')
	{
		return c - 'a' + 10;
	}
	else if ('A' <= c && c <= 'F')
	{
		return c - 'A' + 10;
	}
	else
	{
		return 0;
	}
}

void SeToStr(char *str, UINT value)
{
	char tmp[MAX_SIZE];
	UINT wp = 0;
	UINT len, i;
	if (str == NULL)
	{
		return;
	}

	SeStrCpy(tmp, 0, "");

	while (true)
	{
		UINT a = (UINT)(value % (UINT)10);
		value = value / (UINT)10;
		tmp[wp++] = (char)('0' + a);
		if (value == 0)
		{
			tmp[wp++] = 0;
			break;
		}
	}

	len = SeStrLen(tmp);
	for (i = 0;i < len;i++)
	{
		str[len - i - 1] = tmp[i];
	}
	str[len] = 0;
}

void SeToStr64(char *str, UINT64 value)
{
	char tmp[MAX_SIZE];
	UINT wp = 0;
	UINT len, i;
	if (str == NULL)
	{
		return;
	}

	SeStrCpy(tmp, 0, "");

	while (true)
	{
		UINT a = (UINT)(value % (UINT64)10);
		value = value / (UINT64)10;
		tmp[wp++] = (char)('0' + a);
		if (value == 0)
		{
			tmp[wp++] = 0;
			break;
		}
	}

	len = SeStrLen(tmp);
	for (i = 0;i < len;i++)
	{
		str[len - i - 1] = tmp[i];
	}
	str[len] = 0;
}

UINT SeToInt(char *str)
{
	UINT len, i;
	UINT ret = 0;
	if (str == NULL)
	{
		return 0;
	}

	len = SeStrLen(str);
	for (i = 0;i < len;i++)
	{
		char c = str[i];
		if (c != ',')
		{
			if ('0' <= c && c <= '9')
			{
				ret = ret * (UINT)10 + (UINT)(c - '0');
			}
			else
			{
				break;
			}
		}
	}

	return ret;
}

UINT64 SeToInt64(char *str)
{
	UINT len, i;
	UINT64 ret = 0;
	if (str == NULL)
	{
		return 0;
	}

	len = SeStrLen(str);
	for (i = 0;i < len;i++)
	{
		char c = str[i];
		if (c != ',')
		{
			if ('0' <= c && c <= '9')
			{
				ret = ret * (UINT64)10 + (UINT64)(c - '0');
			}
			else
			{
				break;
			}
		}
	}

	return ret;
}

int SeStrCmpi(char *str1, char *str2)
{
	UINT i;
	if (str1 == NULL && str2 == NULL)
	{
		return 0;
	}
	if (str1 == NULL)
	{
		return 1;
	}
	if (str2 == NULL)
	{
		return -1;
	}

	i = 0;
	while (true)
	{
		char c1, c2;

		c1 = SeToUpper(str1[i]);
		c2 = SeToUpper(str2[i]);
		if (c1 > c2)
		{
			return 1;
		}
		else if (c1 < c2)
		{
			return -1;
		}
		if (str1[i] == 0 || str2[i] == 0)
		{
			return 0;
		}
		i++;
	}
}
int SeStrnCmpi(char *str1, char *str2, UINT count)
{
	UINT i;
	if (str1 == NULL && str2 == NULL)
	{
		return 0;
	}
	if (str1 == NULL)
	{
		return 1;
	}
	if (str2 == NULL)
	{
		return -1;
	}

	i = 0;
	while (true)
	{
		char c1, c2;

		if (i >= count)
		{
			return 0;
		}

		c1 = SeToUpper(str1[i]);
		c2 = SeToUpper(str2[i]);
		if (c1 > c2)
		{
			return 1;
		}
		else if (c1 < c2)
		{
			return -1;
		}
		if (str1[i] == 0 || str2[i] == 0)
		{
			return 0;
		}
		i++;
	}
}

int SeStrCmp(char *str1, char *str2)
{
	UINT i;
	if (str1 == NULL && str2 == NULL)
	{
		return 0;
	}
	if (str1 == NULL)
	{
		return 1;
	}
	if (str2 == NULL)
	{
		return -1;
	}

	i = 0;
	while (true)
	{
		char c1 = str1[i];
		char c2 = str2[i];

		if (c1 > c2)
		{
			return 1;
		}
		else if (c1 < c2)
		{
			return -1;
		}
		if (str1[i] == 0 || str2[i] == 0)
		{
			return 0;
		}
		i++;
	}
}
int SeStrnCmp(char *str1, char *str2, UINT count)
{
	UINT i;
	if (str1 == NULL && str2 == NULL)
	{
		return 0;
	}
	if (str1 == NULL)
	{
		return 1;
	}
	if (str2 == NULL)
	{
		return -1;
	}

	i = 0;
	while (true)
	{
		char c1 = str1[i];
		char c2 = str2[i];

		if (i >= count)
		{
			return 0;
		}

		if (c1 > c2)
		{
			return 1;
		}
		else if (c1 < c2)
		{
			return -1;
		}
		if (str1[i] == 0 || str2[i] == 0)
		{
			return 0;
		}
		i++;
	}
}

void SeStrLower(char *str)
{
	UINT len, i;
	if (str == NULL)
	{
		return;
	}

	len = SeStrLen(str);
	for (i = 0;i < len;i++)
	{
		str[i] = SeToLower(str[i]);
	}
}

void SeStrUpper(char *str)
{
	UINT len, i;
	if (str == NULL)
	{
		return;
	}

	len = SeStrLen(str);
	for (i = 0;i < len;i++)
	{
		str[i] = SeToUpper(str[i]);
	}
}

char SeToUpper(char c)
{
	if ('a' <= c && c <= 'z')
	{
		c += 'Z' - 'z';
	}
	return c;
}

char SeToLower(char c)
{
	if ('A' <= c && c <= 'Z')
	{
		c += 'z' - 'Z';
	}
	return c;
}

UINT SeStrCat(char *dst, UINT size, char *src)
{
	UINT len1, len2, len_test;
	if (dst == NULL || src == NULL)
	{
		return 0;
	}
	if (size == 0)
	{
		size = 0x7fffffff;
	}

	len1 = SeStrLen(dst);
	len2 = SeStrLen(src);
	len_test = len1 + len2 + 1;
	if (len_test > size)
	{
		if (len2 <= (len_test - size))
		{
			return 0;
		}
		len2 -= len_test - size;
	}

	SeCopy(dst + len1, src, len2);
	dst[len1 + len2] = '\0';

	return len1 + len2;
}

UINT SeStrCpy(char *dst, UINT size, char *src)
{
	UINT len;
	if (dst == src)
	{
		return SeStrLen(src);
	}
	if (dst == NULL || src == NULL)
	{
		if (src == NULL && dst != NULL)
		{
			dst[0] = '\0';
		}
		return 0;
	}
	if (size == 1)
	{
		dst[0] = '\0';
		return 0;
	}
	if (size == 0)
	{
		size = 0x7fffffff;
	}

	len = SeStrLen(src);
	if (len <= (size - 1))
	{
		SeCopy(dst, src, len + 1);
	}
	else
	{
		len = size - 1;
		SeCopy(dst, src, len);
		dst[len] = '\0';
	}

	return len;
}

bool SeStrCheckSize(char *str, UINT size)
{
	if (str == NULL || size == 0)
	{
		return false;
	}

	return SeStrCheckLen(str, size - 1);
}

bool SeStrCheckLen(char *str, UINT len)
{
	UINT n, i;
	if (str == NULL)
	{
		return false;
	}

	n = 0;

	for (i = 0;;i++)
	{
		if (str[i] == '\0')
		{
			return true;
		}
		n++;
		if (n > len)
		{
			return false;
		}
	}
}

UINT SeStrSize(char *str)
{
	if (str == NULL)
	{
		return 0;
	}

	return SeStrLen(str) + sizeof(char);
}

UINT SeStrLen(char *str)
{
	UINT n;
	if (str == NULL)
	{
		return 0;
	}

	n = 0;

	while (*(str++) != '\0')
	{
		n++;
	}

	return n;
}

