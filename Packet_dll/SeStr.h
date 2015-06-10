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

#ifndef	SESTR_H
#define	SESTR_H

struct SE_TOKEN_LIST
{
	UINT NumTokens;
	char **Token;
};

UINT SeStrLen(char *str);
UINT SeStrSize(char *str);
bool SeStrCheckLen(char *str, UINT len);
bool SeStrCheckSize(char *str, UINT size);
UINT SeStrCpy(char *dst, UINT size, char *src);
UINT SeStrCat(char *dst, UINT size, char *src);
char SeToUpper(char c);
char SeToLower(char c);
void SeStrUpper(char *str);
void SeStrLower(char *str);
int SeStrCmp(char *str1, char *str2);
int SeStrnCmp(char *str1, char *str2, UINT count);
int SeStrCmpi(char *str1, char *str2);
int SeStrnCmpi(char *str1, char *str2, UINT count);
UINT64 SeToInt64(char *str);
UINT SeToInt(char *str);
void SeToStr64(char *str, UINT64 value);
void SeToStr(char *str, UINT value);
void SeToHex(char *str, UINT value);
void SeToHex64(char *str, UINT64 value);
UINT SeHexToInt(char *str);
UINT64 SeHexToInt64(char *str);
char Se4BitToHex(UINT value);
UINT SeHexTo4Bit(char c);
void SeTrim(char *str);
void SeTrimRight(char *str);
void SeTrimLeft(char *str);
char *SeCopyStr(char *str);
char *SeTrimCopy(char *str);
UINT SeReplaceStri(char *dst, UINT size, char *string, char *old_keyword, char *new_keyword);
UINT SeReplaceStr(char *dst, UINT size, char *string, char *old_keyword, char *new_keyword);
UINT SeReplaceStrEx(char *dst, UINT size, char *string, char *old_keyword, char *new_keyword, bool case_sensitive);
UINT SeCalcReplaceStrEx(char *string, char *old_keyword, char *new_keyword, bool case_sensitive);
UINT SeSearchStr(char *string, char *keyword, UINT start);
UINT SeSearchStri(char *string, char *keyword, UINT start);
UINT SeSearchStrEx(char *string, char *keyword, UINT start, bool case_sensitive);
void SeTrimCrlf(char *str);
bool SeEndWith(char *str, char *key);
bool SeStartWith(char *str, char *key);
bool SeIsEmptyStr(char *str);
char *SeNormalizeCrlf(char *str);
SE_TOKEN_LIST *SeParseToken(char *str, char *split_chars);
SE_TOKEN_LIST *SeParseTokenWithNullStr(char *str, char *split_chars);
void SeFreeToken(SE_TOKEN_LIST *t);
char *SeDefaultTokenSplitChars();
bool SeIsCharInStr(char *str, char c);
SE_TOKEN_LIST *SeNullTokenList();
void SeToStr3(char *str, UINT size, UINT64 v);
SE_TOKEN_LIST *SeUniqueToken(SE_TOKEN_LIST *t);
bool SeIsAllUpperStr(char *str);
bool SeIsAllLowerStr(char *str);
char *SeMakeCharArray(char c, UINT count);
char *SeFormatEx(char *fmt, void **arg_list);
void SeFormatArgs(char *buf, UINT size, char *fmt, void **args);
void SeFormat(char *buf, UINT size, char *fmt, ...);
void SeBinToStrEx(char *str, UINT str_size, void *data, UINT data_size);
void SeBinToStr(char *str, UINT str_size, void *data, UINT data_size);
SE_BUF *SeStrToBin(char *str);
bool SeStrToBinEx(void *dst, UINT dst_size, char *str);
bool SeStrToMac(UCHAR *mac_address, char *str);
void SeMacToStr(char *str, UINT str_size, UCHAR *mac_address);
char *SeReadNextLine(SE_BUF *b);
UINT SeUniToStr(char *str, UINT size, wchar_t *s);
UINT SeCalcUniToStr(wchar_t *s);
UINT SeStrToUni(wchar_t *s, UINT size, char *str);
UINT SeCalcStrToUni(char *str);
UINT SeUniStrLen(wchar_t *str);
UINT SeUniStrCpy(wchar_t *dst, UINT size, wchar_t *src);
int SeUniStrCmpi(wchar_t *str1, wchar_t *str2);
int SeUniStrCmp(wchar_t *str1, wchar_t *str2);
void SeUniStrLower(wchar_t *str);
void SeUniStrUpper(wchar_t *str);
wchar_t SeUniToLower(wchar_t c);
wchar_t SeUniToUpper(wchar_t c);
UINT SeUniStrCat(wchar_t *dst, UINT size, wchar_t *src);
UINT SeUniStrCatLeft(wchar_t *dst, UINT size, wchar_t *src);
wchar_t *SeUniCopyStr(wchar_t *str);
wchar_t *SeCopyUniStr(wchar_t *str);
void SeGetDirNameFromFilePath(char *dst, UINT size, char *filepath);

#endif	// SESTR_H

