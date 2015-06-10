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

#ifndef	SEMEMORY_H
#define SEMEMORY_H

#define	SE_INIT_BUF_SIZE			10240
#define	SE_FIFO_INIT_MEM_SIZE		4096
#define	SE_FIFO_REALLOC_MEM_SIZE	(65536 * 10)
#define	SE_INIT_NUM_RESERVED		32

struct SE_BUF
{
	void *Buf;
	UINT Size;
	UINT SizeReserved;
	UINT Current;
};

struct SE_FIFO
{
	void *p;
	UINT pos, size, memsize;
};

struct SE_LIST
{
	UINT num_item, num_reserved;
	void **p;
	SE_CALLBACK_COMPARE *cmp;
	bool sorted;
};

struct SE_QUEUE
{
	UINT num_item;
	SE_FIFO *fifo;
};

struct SE_STACK
{
	UINT num_item, num_reserved;
	void **p;
};

#define	SE_LIST_DATA(o, i)		(((o) != NULL) ? ((o)->p[(i)]) : NULL)
#define	SE_LIST_NUM(o)			(((o) != NULL) ? (o)->num_item : 0)
#define SE_GETARG(ret, start, index)		\
{											\
	UCHAR *pointer = (UCHAR *)(&start);		\
	void **pointer2;						\
	UINT index_copy = (index);				\
	pointer += (UINT)(sizeof(void *) * (index_copy + 1));	\
	pointer2 = (void **)pointer;			\
	ret = *pointer2;						\
}
#define SE_BUILD_ARGLIST(start)				\
	((void **)(&start)) + 1

void SeZero(void *addr, UINT size);
void SeCopy(void *dst, void *src, UINT size);
int SeCmp(void *addr1, void *addr2, UINT size);
bool SeCmpEx(void *addr1, UINT size1, void *addr2, UINT size2);
bool SeIsLittleEndian();
bool SeIsBigEndian();
void *SeMalloc(UINT size);
void *SeReAlloc(void *addr, UINT size);
void SeFree(void *addr);
void *SeZeroMalloc(UINT size);
UINT SeMemSize(void *addr);
void *SeClone(void *addr, UINT size);
UINT64 SeSwap64(UINT64 value);
UINT SeSwap32(UINT value);
USHORT SeSwap16(USHORT value);
void SeSwap(void *buf, UINT size);
UINT64 SeEndian64(UINT64 value);
UINT SeEndian32(UINT value);
USHORT SeEndian16(USHORT value);
bool SeIsZero(void *data, UINT size);
char *SeB64Encode(void *source, UINT len);
SE_BUF *SeB64Decode(char *source);
char SeB64CodeToChar(BYTE c);
char SeB64CharToCode(char c);

SE_BUF *SeNewBuf();
SE_BUF *SeMemToBuf(void *data, UINT size);
SE_BUF *SeCloneBuf(SE_BUF *b);
void SeClearBuf(SE_BUF *b);
void SeWriteBuf(SE_BUF *b, void *buf, UINT size);
void SeWriteBufBuf(SE_BUF *b, SE_BUF *bb);
UINT SeReadBuf(SE_BUF *b, void *buf, UINT size);
SE_BUF *SeReadBufFromBuf(SE_BUF *b, UINT size);
SE_BUF *SeReadRemainBuf(SE_BUF *b);
void SeAdjustBufSize(SE_BUF *b, UINT new_size);
void SeSeekBuf(SE_BUF *b, UINT offset, int mode);
void SeFreeBuf(SE_BUF *b);
void SeFreeBufWithoutBuffer(SE_BUF *b);
UINT SeReadBufInt(SE_BUF *b);
UINT64 SeReadBufInt64(SE_BUF *b);
bool SeWriteBufInt(SE_BUF *b, UINT value);
bool SeWriteBufInt64(SE_BUF *b, UINT64 value);
bool SeReadBufStr(SE_BUF *b, char *str, UINT size);
bool SeWriteBufStr(SE_BUF *b, char *str);
void SeWriteBufLine(SE_BUF *b, char *str);
void SeAddBufStr(SE_BUF *b, char *str);
bool SeCmpBuf(SE_BUF *b1, SE_BUF *b2);

SE_FIFO *SeNewFifo();
void SeFreeFifo(SE_FIFO *f);
UINT SePeekFifo(SE_FIFO *f, void *p, UINT size);
UINT SeReadFifo(SE_FIFO *f, void *p, UINT size);
void SeWriteFifo(SE_FIFO *f, void *p, UINT size);
void SeClearFifo(SE_FIFO *f);
UINT SeFifoSize(SE_FIFO *f);

SE_LIST *SeNewList(SE_CALLBACK_COMPARE *cmp);
void SeFreeList(SE_LIST *o);
void *SeSearch(SE_LIST *o, void *target);
void *SeBSearch(void *key, void *base, UINT num, UINT width, int (*compare_function)(void *, void *));
void SeSort(SE_LIST *o);
void SeQSort(void *base, UINT num, UINT width, int (*compare_function)(void *, void *));
void SeFastSwap(UCHAR *a, UCHAR *b, UINT width);
void SeAdd(SE_LIST *o, void *p);
void SeInsert(SE_LIST *o, void *p);
bool SeDelete(SE_LIST *o, void *p);
void SeDeleteAll(SE_LIST *o);
void SeCopyToArray(SE_LIST *o, void *p);
void *SeToArray(SE_LIST *o);
SE_LIST *SeCloneList(SE_LIST *o);
void SeSetCmp(SE_LIST *o, SE_CALLBACK_COMPARE *cmp);
void SeSetSortFlag(SE_LIST *o, bool sorted);
int SeCompareStr(void *p1, void *p2);
bool SeInsertStr(SE_LIST *o, char *str);
bool SeIsInList(SE_LIST *o, void *p);
bool SeIsInListStr(SE_LIST *o, char *str);
bool SeReplaceListPointer(SE_LIST *o, void *oldptr, void *newptr);

SE_QUEUE *SeNewQueue();
void SeFreeQueue(SE_QUEUE *q);
void *SeGetNext(SE_QUEUE *q);
UINT SeGetNextInt(SE_QUEUE *q);
void SeInsertQueue(SE_QUEUE *q, void *p);
void SeInsertQueueInt(SE_QUEUE *q, UINT value);

SE_STACK *SeNewStack();
void SeFreeStack(SE_STACK *s);
void SePush(SE_STACK *s, void *p);
void *SePop(SE_STACK *s);

void SeSysLog(char *type, char *message);



#endif	// SEMEMORY_H

