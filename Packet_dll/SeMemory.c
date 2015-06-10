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


char *SeB64Encode(void *source, UINT len)
{
	BYTE *src;
	UINT i, j;
	char *set;
	UINT set_size;
	char *ret;

	set_size = (len + 8) * 2;
	set = SeZeroMalloc(set_size);

	src = (BYTE *)source;
	j = 0;
	i = 0;

	if (!len)
	{
		return 0;
	}
	while (true)
	{
		if (i >= len)
		{
			break;
		}
		if (set)
		{
			set[j] = SeB64CodeToChar((src[i]) >> 2);
		}
		if (i + 1 >= len)
		{
			if (set)
			{
				set[j + 1] = SeB64CodeToChar((src[i] & 0x03) << 4);
				set[j + 2] = '=';
				set[j + 3] = '=';
			}
			break;
		}
		if (set)
		{
			set[j + 1] = SeB64CodeToChar(((src[i] & 0x03) << 4) + ((src[i + 1] >> 4)));
		}
		if (i + 2 >= len)
		{
			if (set)
			{
				set[j + 2] = SeB64CodeToChar((src[i + 1] & 0x0f) << 2);
				set[j + 3] = '=';
			}
			break;
		}
		if (set)
		{
			set[j + 2] = SeB64CodeToChar(((src[i + 1] & 0x0f) << 2) + ((src[i + 2] >> 6)));
			set[j + 3] = SeB64CodeToChar(src[i + 2] & 0x3f);
		}
		i += 3;
		j += 4;
	}

	ret = SeCopyStr(set);
	SeFree(set);

	return ret;
}

SE_BUF *SeB64Decode(char *source)
{
	UINT i, j;
	char a1, a2, a3, a4;
	char *src;
	UINT f1, f2, f3, f4;
	UINT len;
	UINT set_size;
	UCHAR *set;
	SE_BUF *b;
	UCHAR zero_char = 0;

	len = SeStrLen(source);
	src = source;
	i = 0;
	j = 0;

	set_size = (len + 2) * 2;
	set = SeZeroMalloc(set_size);

	while (true)
	{
		f1 = f2 = f3 = f4 = 0;
		if (i >= len)
		{
			break;
		}
		f1 = 1;
		a1 = SeB64CharToCode(src[i]);
		if (a1 == -1)
		{
			f1 = 0;
		}
		if (i >= len + 1)
		{
			a2 = 0;
		}
		else
		{
			a2 = SeB64CharToCode(src[i + 1]);
			f2 = 1;
			if (a2 == -1)
			{
				f2 = 0;
			}
		}
		if (i >= len + 2)
		{
			a3 = 0;
		}
		else
		{
			a3 = SeB64CharToCode(src[i + 2]);
			f3 = 1;
			if (a3 == -1)
			{
				f3 = 0;
			}
		}
		if (i >= len + 3)
		{
			a4 = 0;
		}
		else
		{
			a4 = SeB64CharToCode(src[i + 3]);
			f4 = 1;
			if (a4 == -1)
			{
				f4 = 0;
			}
		}
		if (f1 && f2)
		{
			if (set)
			{
				set[j] = (a1 << 2) + (a2 >> 4);
			}
			j++;
		}
		if (f2 && f3)
		{
			if (set)
			{
				set[j] = (a2 << 4) + (a3 >> 2);
			}
			j++;
		}
		if (f3 && f4)
		{
			if (set)
			{
				set[j] = (a3 << 6) + a4;
			}
			j++;
		}
		i += 4;
	}

	b = SeNewBuf();
	SeWriteBuf(b, set, j);
	SeWriteBuf(b, &zero_char, sizeof(zero_char));
	b->Size--;

	SeFree(set);

	SeSeekBuf(b, 0, 0);

	return b;
}

char SeB64CodeToChar(BYTE c)
{
	BYTE r;
	r = '=';
	if (c <= 0x19)
	{
		r = c + 'A';
	}
	if (c >= 0x1a && c <= 0x33)
	{
		r = c - 0x1a + 'a';
	}
	if (c >= 0x34 && c <= 0x3d)
	{
		r = c - 0x34 + '0';
	}
	if (c == 0x3e)
	{
		r = '+';
	}
	if (c == 0x3f)
	{
		r = '/';
	}
	return r;
}

char SeB64CharToCode(char c)
{
	if (c >= 'A' && c <= 'Z')
	{
		return c - 'A';
	}
	if (c >= 'a' && c <= 'z')
	{
		return c - 'a' + 0x1a;
	}
	if (c >= '0' && c <= '9')
	{
		return c - '0' + 0x34;
	}
	if (c == '+')
	{
		return 0x3e;
	}
	if (c == '/')
	{
		return 0x3f;
	}
	if (c == '=')
	{
		return -1;
	}
	return 0;
}

bool SeIsZero(void *data, UINT size)
{
	UINT i;
	UCHAR *c = (UCHAR *)data;
	if (data == NULL || size == 0)
	{
		return true;
	}

	for (i = 0;i < size;i++)
	{
		if (c[i] != 0)
		{
			return false;
		}
	}

	return true;
}

SE_STACK *SeNewStack()
{
	SE_STACK *s;

	s = SeZeroMalloc(sizeof(SE_STACK));
	s->num_item = 0;
	s->num_reserved = SE_INIT_NUM_RESERVED;
	s->p = SeMalloc(sizeof(void *) * s->num_reserved);

	return s;
}

void SeFreeStack(SE_STACK *s)
{
	if (s == NULL)
	{
		return;
	}

	SeFree(s->p);
	SeFree(s);
}

void SePush(SE_STACK *s, void *p)
{
	UINT i;
	if (s == NULL || p == NULL)
	{
		return;
	}

	i = s->num_item;
	s->num_item++;
	if (s->num_item > s->num_reserved)
	{
		s->num_reserved = s->num_reserved * 2;
		s->p = SeReAlloc(s->p, sizeof(void *) * s->num_reserved);
	}
	s->p[i] = p;
}

void *SePop(SE_STACK *s)
{
	void *ret;
	if (s == NULL)
	{
		return NULL;
	}
	if (s->num_item == 0)
	{
		return NULL;
	}

	ret = s->p[s->num_item - 1];
	s->num_item--;
	if ((s->num_item * 2) <= s->num_reserved)
	{
		if (s->num_reserved >= (SE_INIT_NUM_RESERVED * 2))
		{
			s->num_reserved = s->num_reserved / 2;
			s->p = SeReAlloc(s->p, sizeof(void *) * s->num_reserved);
		}
	}

	return ret;
}

SE_QUEUE *SeNewQueue()
{
	SE_QUEUE *q;

	q = SeZeroMalloc(sizeof(SE_QUEUE));
	q->num_item = 0;
	q->fifo = SeNewFifo();

	return q;
}

void SeFreeQueue(SE_QUEUE *q)
{
	// 引数チェック
	if (q == NULL)
	{
		return;
	}

	SeFreeFifo(q->fifo);
	SeFree(q);
}

void *SeGetNext(SE_QUEUE *q)
{
	void *p = NULL;
	if (q == NULL)
	{
		return NULL;
	}

	if (q->num_item == 0)
	{
		return NULL;
	}

	SeReadFifo(q->fifo, &p, sizeof(void *));
	q->num_item--;

	return p;
}

UINT SeGetNextInt(SE_QUEUE *q)
{
	UINT *p;
	UINT ret;
	if (q == NULL)
	{
		return 0;
	}

	p = SeGetNext(q);
	if (p == NULL)
	{
		return 0;
	}

	ret = *p;
	SeFree(p);

	return *p;
}

void SeInsertQueue(SE_QUEUE *q, void *p)
{
	if (q == NULL || p == NULL)
	{
		return;
	}

	SeWriteFifo(q->fifo, &p, sizeof(void *));

	q->num_item++;
}

void SeInsertQueueInt(SE_QUEUE *q, UINT value)
{
	UINT *p;
	if (q == NULL)
	{
		return;
	}

	p = SeClone(&value, sizeof(UINT));

	SeInsertQueue(q, p);
}

bool SeReplaceListPointer(SE_LIST *o, void *oldptr, void *newptr)
{
	UINT i;
	if (o == NULL || oldptr == NULL || newptr == NULL)
	{
		return false;
	}

	for (i = 0;i < SE_LIST_NUM(o);i++)
	{
		void *p = SE_LIST_DATA(o, i);

		if (p == oldptr)
		{
			o->p[i] = newptr;
			return true;
		}
	}

	return false;
}

bool SeIsInListStr(SE_LIST *o, char *str)
{
	UINT i;
	if (o == NULL || str == NULL)
	{
		return false;
	}

	for (i = 0;i < SE_LIST_NUM(o);i++)
	{
		char *s = SE_LIST_DATA(o, i);

		if (SeStrCmpi(s, str) == 0)
		{
			return true;
		}
	}

	return false;
}

bool SeIsInList(SE_LIST *o, void *p)
{
	UINT i;
	if (o == NULL || p == NULL)
	{
		return false;
	}

	for (i = 0;i < SE_LIST_NUM(o);i++)
	{
		void *q = SE_LIST_DATA(o, i);
		if (p == q)
		{
			return true;
		}
	}

	return false;
}

bool SeInsertStr(SE_LIST *o, char *str)
{
	if (o == NULL || str == NULL)
	{
		return false;
	}

	if (SeSearch(o, str) == NULL)
	{
		SeInsert(o, str);

		return true;
	}

	return false;
}

int SeCompareStr(void *p1, void *p2)
{
	char *s1, *s2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	s1 = *(char **)p1;
	s2 = *(char **)p2;

	return SeStrCmpi(s1, s2);
}

void SeSetSortFlag(SE_LIST *o, bool sorted)
{
	if (o == NULL)
	{
		return;
	}

	o->sorted = sorted;
}

void SeSetCmp(SE_LIST *o, SE_CALLBACK_COMPARE *cmp)
{
	if (o == NULL || cmp == NULL)
	{
		return;
	}

	if (o->cmp != cmp)
	{
		o->cmp = cmp;
		o->sorted = false;
	}
}

SE_LIST *SeCloneList(SE_LIST *o)
{
	SE_LIST *n = SeNewList(o->cmp);

	SeFree(n->p);
	n->p = SeToArray(o);
	n->num_item = n->num_reserved = SE_LIST_NUM(o);
	n->sorted = o->sorted;

	return n;
}

void *SeToArray(SE_LIST *o)
{
	void *p;
	if (o == NULL)
	{
		return NULL;
	}

	p = SeMalloc(sizeof(void *) * SE_LIST_NUM(o));
	SeCopyToArray(o, p);

	return p;
}

void SeCopyToArray(SE_LIST *o, void *p)
{
	if (o == NULL || p == NULL)
	{
		return;
	}

	SeCopy(p, o->p, sizeof(void *) * o->num_item);
}

void SeDeleteAll(SE_LIST *o)
{
	if (o == NULL)
	{
		return;
	}

	o->num_item = 0;
	o->num_reserved = SE_INIT_NUM_RESERVED;
	o->p = SeReAlloc(o->p, sizeof(void *) * SE_INIT_NUM_RESERVED);
}

bool SeDelete(SE_LIST *o, void *p)
{
	UINT i, n;
	if (o == NULL || p == NULL)
	{
		return false;
	}

	for (i = 0;i < o->num_item;i++)
	{
		if (o->p[i] == p)
		{
			break;
		}
	}
	if (i == o->num_item)
	{
		return false;
	}

	n = i;
	for (i = n;i < (o->num_item - 1);i++)
	{
		o->p[i] = o->p[i + 1];
	}
	o->num_item--;
	if ((o->num_item * 2) <= o->num_reserved)
	{
		if (o->num_reserved > (SE_INIT_NUM_RESERVED * 2))
		{
			o->num_reserved = o->num_reserved / 2;
			o->p = SeReAlloc(o->p, sizeof(void *) * o->num_reserved);
		}
	}

	return true;
}

void SeInsert(SE_LIST *o, void *p)
{
	int low, high, middle;
	UINT pos;
	int i;
	if (o == NULL || p == NULL)
	{
		return;
	}

	if (o->cmp == NULL)
	{
		SeAdd(o, p);
		return;
	}

	if (o->sorted == false)
	{
		SeSort(o);
	}

	low = 0;
	high = SE_LIST_NUM(o) - 1;

	pos = INFINITE;

	while (low <= high)
	{
		int ret;

		middle = (low + high) / 2;
		ret = o->cmp(&(o->p[middle]), &p);

		if (ret == 0)
		{
			pos = middle;
			break;
		}
		else if (ret > 0)
		{
			high = middle - 1;
		}
		else
		{
			low = middle + 1;
		}
	}

	if (pos == INFINITE)
	{
		pos = low;
	}

	o->num_item++;
	if (o->num_item > o->num_reserved)
	{
		o->num_reserved *= 2;
		o->p = SeReAlloc(o->p, sizeof(void *) * o->num_reserved);
	}

	if (SE_LIST_NUM(o) >= 2)
	{
		for (i = (SE_LIST_NUM(o) - 2);i >= (int)pos;i--)
		{
			o->p[i + 1] = o->p[i];
		}
	}

	o->p[pos] = p;
}

void SeAdd(SE_LIST *o, void *p)
{
	UINT i;
	if (o == NULL || p == NULL)
	{
		return;
	}

	i = o->num_item;
	o->num_item++;

	if (o->num_item > o->num_reserved)
	{
		o->num_reserved = o->num_reserved * 2;
		o->p = SeReAlloc(o->p, sizeof(void *) * o->num_reserved);
	}

	o->p[i] = p;
	o->sorted = false;
}

void SeSort(SE_LIST *o)
{
	// 引数チェック
	if (o == NULL || o->cmp == NULL)
	{
		return;
	}

	SeQSort(o->p, o->num_item, sizeof(void *), (int(*)(void *, void *))o->cmp);
	o->sorted = true;
}

void *SeSearch(SE_LIST *o, void *target)
{
	void **ret;
	if (o == NULL || target == NULL)
	{
		return NULL;
	}
	if (o->cmp == NULL)
	{
		return NULL;
	}

	if (o->sorted == false)
	{
		SeSort(o);
	}

	ret = (void **)SeBSearch(&target, o->p, o->num_item, sizeof(void *),
		(int(*)(void *, void *))o->cmp);

	if (ret != NULL)
	{
		return *ret;
	}
	else
	{
		return NULL;
	}
}

#define SE_QSORT_STACKSIZE	(sizeof(void *) * 8 - 2)

void SeQSort(void *base, UINT num, UINT width, int (*compare_function)(void *, void *))
{
	UCHAR *low;
	UCHAR *high;
	UCHAR *middle;
	UCHAR *low2;
	UCHAR *high2;
	UINT size;
	UCHAR *low_stack[SE_QSORT_STACKSIZE], *high_stack[SE_QSORT_STACKSIZE];
	int stack_pointer = 0;

	if (num <= 1)
	{
		return;
	}

	low = (UCHAR *)base;
	high = (UCHAR *)base + width * (num - 1);

LABEL_RECURSE:

	size = (UINT)((high - low) / width + 1);

	middle = low + (size / 2) * width;

	if (compare_function(low, middle) > 0)
	{
		SeFastSwap(low, middle, width);
	}

	if (compare_function(low, high) > 0)
	{
		SeFastSwap(low, high, width);
	}

	if (compare_function(middle, high) > 0)
	{
		SeFastSwap(middle, high, width);
	}

	low2 = low;
	high2 = high;

	while (true)
	{
		if (middle > low2)
		{
			do
			{
				low2 += width;
			}
			while (low2 < middle && compare_function(low2, middle) <= 0);
		}

		if (middle <= low2)
		{
			do
			{
				low2 += width;
			}
			while (low2 <= high && compare_function(low2, middle) <= 0);
		}

		do
		{
			high2 -= width;
		}
		while (high2 > middle && compare_function(high2, middle) > 0);

		if (high2 < low2)
		{
			break;
		}

		SeFastSwap(low2, high2, width);

		if (middle == high2)
		{
			middle = low2;
		}
	}

	high2 += width;

	if (middle < high2)
	{
		do
		{
			high2 -= width;
		}
		while (high2 > middle && compare_function(high2, middle) == 0);
	}

	if (middle >= high2)
	{
		do
		{
			high2 -= width;
		}
		while (high2 > low && compare_function(high2, middle) == 0);
	}

	if ((high2 - low) >= (high - low2))
	{
		if (low < high2)
		{
			low_stack[stack_pointer] = low;
			high_stack[stack_pointer] = high2;
			stack_pointer++;
		}

		if (low2 < high)
		{
			low = low2;
			goto LABEL_RECURSE;
		}
	}
	else
	{
		if (low2 < high)
		{
			low_stack[stack_pointer] = low2;
			high_stack[stack_pointer] = high;
			stack_pointer++;
		}

		if (low < high2)
		{
			high = high2;
			goto LABEL_RECURSE;
		}
	}

	stack_pointer--;
	if (stack_pointer >= 0)
	{
		low = low_stack[stack_pointer];
		high = high_stack[stack_pointer];

		goto LABEL_RECURSE;
	}
}

void SeFastSwap(UCHAR *a, UCHAR *b, UINT width)
{
	UCHAR tmp;
	if (a == b)
	{
		return;
	}

	while (width--)
	{
		tmp = *a;
		*a++ = *b;
		*b++ = tmp;
	}
}

void *SeBSearch(void *key, void *base, UINT num, UINT width, int (*compare_function)(void *, void *))
{
	UCHAR *low = (UCHAR *)base;
	UCHAR *high = (UCHAR *)base + width * (num - 1);
	UCHAR *middle;
	UINT half;
	int ret;

	while (low <= high)
	{
		if ((half = (num / 2)) != 0)
		{
			middle = low + (((num % 2) != 0) ? half : (half - 1)) * width;
			ret = compare_function(key, middle);

			if (ret == 0)
			{
				return middle;
			}
			else if (ret < 0)
			{
				high = middle - width;
				num = ((num % 2) != 0) ? half : half - 1;
			}
			else
			{
				low = middle + width;
				num = half;
			}
		}
		else if (num != 0)
		{
			if (compare_function(key, low) == 0)
			{
				return low;
			}
			else
			{
				return NULL;
			}
		}
		else
		{
			break;
		}
	}

	return NULL;
}

void SeFreeList(SE_LIST *o)
{
	if (o == NULL)
	{
		return;
	}

	SeFree(o->p);
	SeFree(o);
}

SE_LIST *SeNewList(SE_CALLBACK_COMPARE *cmp)
{
	SE_LIST *o;

	o = SeZeroMalloc(sizeof(SE_LIST));

	o->num_item = 0;
	o->num_reserved = SE_INIT_NUM_RESERVED;
	o->p = SeMalloc(sizeof(void *) * o->num_reserved);
	o->cmp = cmp;
	o->sorted = true;

	return o;
}

UINT SeFifoSize(SE_FIFO *f)
{
	if (f == NULL)
	{
		return 0;
	}

	return f->size;
}

void SeClearFifo(SE_FIFO *f)
{
	if (f == NULL)
	{
		return;
	}

	f->size = f->pos = 0;
	f->memsize = SE_FIFO_INIT_MEM_SIZE;
	f->p = SeReAlloc(f->p, f->memsize);
}

void SeWriteFifo(SE_FIFO *f, void *p, UINT size)
{
	UINT i, need_size;
	bool realloc_flag;
	if (f == NULL || size == 0)
	{
		return;
	}

	i = f->size;
	f->size += size;
	need_size = f->pos + f->size;
	realloc_flag = false;

	while (need_size > f->memsize)
	{
		f->memsize = MAX(f->memsize, SE_FIFO_INIT_MEM_SIZE) * 3;
		realloc_flag = true;
	}

	if (realloc_flag)
	{
		f->p = SeReAlloc(f->p, f->memsize);
	}

	if (p != NULL)
	{
		SeCopy((UCHAR *)f->p + f->pos + i, p, size);
	}
}

UINT SeReadFifo(SE_FIFO *f, void *p, UINT size)
{
	UINT read_size;
	if (f == NULL || size == 0)
	{
		return 0;
	}

	read_size = MIN(size, f->size);
	if (read_size == 0)
	{
		return 0;
	}
	if (p != NULL)
	{
		SeCopy(p, (UCHAR *)f->p + f->pos, read_size);
	}
	f->pos += read_size;
	f->size -= read_size;

	if (f->size == 0)
	{
		f->pos = 0;
	}

	if (f->pos >= SE_FIFO_INIT_MEM_SIZE &&
		f->memsize >= SE_FIFO_REALLOC_MEM_SIZE &&
		(f->memsize / 2) > f->size)
	{
		void *new_p;
		UINT new_size;

		new_size = MAX(f->memsize / 2, SE_FIFO_INIT_MEM_SIZE);
		new_p = SeMalloc(new_size);
		SeCopy(new_p, (UCHAR *)f->p + f->pos, f->size);

		SeFree(f->p);

		f->memsize = new_size;
		f->p = new_p;
		f->pos = 0;
	}

	return read_size;
}

UINT SePeekFifo(SE_FIFO *f, void *p, UINT size)
{
	UINT read_size;
	if (f == NULL || size == 0)
	{
		return 0;
	}

	read_size = MIN(size, f->size);
	if (read_size == 0)
	{
		return 0;
	}

	if (p != NULL)
	{
		SeCopy(p, (UCHAR *)f->p + f->pos, read_size);
	}

	return read_size;
}

void SeFreeFifo(SE_FIFO *f)
{
	if (f == NULL)
	{
		return;
	}

	SeFree(f->p);
	SeFree(f);
}

SE_FIFO *SeNewFifo()
{
	SE_FIFO *f;

	f = SeMalloc(sizeof(SE_FIFO));

	f->size = f->pos = 0;
	f->memsize = SE_FIFO_INIT_MEM_SIZE;
	f->p = SeMalloc(SE_FIFO_INIT_MEM_SIZE);

	return f;
}

UINT SeReadBuf(SE_BUF *b, void *buf, UINT size)
{
	UINT size_read;
	if (b == NULL || size == 0)
	{
		return 0;
	}

	if (b->Buf == NULL)
	{
		SeZero(buf, size);
		return 0;
	}
	size_read = size;
	if ((b->Current + size) >= b->Size)
	{
		size_read = b->Size - b->Current;
		if (buf != NULL)
		{
			SeZero((UCHAR *)buf + size_read, size - size_read);
		}
	}

	if (buf != NULL)
	{
		SeCopy(buf, (UCHAR *)b->Buf + b->Current, size_read);
	}

	b->Current += size_read;

	return size_read;
}

void SeAddBufStr(SE_BUF *b, char *str)
{
	if (b == NULL || str == NULL)
	{
		return;
	}

	SeWriteBuf(b, str, SeStrLen(str));
}

bool SeWriteBufStr(SE_BUF *b, char *str)
{
	UINT len;
	if (b == NULL || str == NULL)
	{
		return false;
	}

	len = SeStrLen(str);
	if (SeWriteBufInt(b, len + 1) == false)
	{
		return false;
	}

	SeWriteBuf(b, str, len);

	return true;
}

bool SeReadBufStr(SE_BUF *b, char *str, UINT size)
{
	UINT len;
	UINT read_size;
	if (b == NULL || str == NULL || size == 0)
	{
		return false;
	}

	len = SeReadBufInt(b);
	if (len == 0)
	{
		return false;
	}
	len--;
	if (len <= (size - 1))
	{
		size = len + 1;
	}

	read_size = MIN(len, (size - 1));

	if (SeReadBuf(b, str, read_size) != read_size)
	{
		return false;
	}
	if (read_size < len)
	{
		SeReadBuf(b, NULL, len - read_size);
	}
	str[len] = 0;

	return true;
}

bool SeWriteBufInt64(SE_BUF *b, UINT64 value)
{
	if (b == NULL)
	{
		return false;
	}

	value = SeEndian64(value);

	SeWriteBuf(b, &value, sizeof(UINT64));
	return true;
}

bool SeWriteBufInt(SE_BUF *b, UINT value)
{
	if (b == NULL)
	{
		return false;
	}

	value = SeEndian32(value);

	SeWriteBuf(b, &value, sizeof(UINT));
	return true;
}

UINT64 SeReadBufInt64(SE_BUF *b)
{
	UINT64 value;
	if (b == NULL)
	{
		return 0;
	}

	if (SeReadBuf(b, &value, sizeof(UINT64)) != sizeof(UINT64))
	{
		return 0;
	}
	return SeEndian64(value);
}

UINT SeReadBufInt(SE_BUF *b)
{
	UINT value;
	if (b == NULL)
	{
		return 0;
	}

	if (SeReadBuf(b, &value, sizeof(UINT)) != sizeof(UINT))
	{
		return 0;
	}
	return SeEndian32(value);
}

void SeAdjustBufSize(SE_BUF *b, UINT new_size)
{
	if (b == NULL)
	{
		return;
	}

	if (b->SizeReserved >= new_size)
	{
		return;
	}

	while (b->SizeReserved < new_size)
	{
		b->SizeReserved = b->SizeReserved * 2;
	}
	b->Buf = SeReAlloc(b->Buf, b->SizeReserved);
}

void SeSeekBuf(SE_BUF *b, UINT offset, int mode)
{
	UINT new_pos;
	if (b == NULL)
	{
		return;
	}

	if (mode == 0)
	{
		new_pos = offset;
	}
	else
	{
		if (mode > 0)
		{
			new_pos = b->Current + offset;
		}
		else
		{
			if (b->Current >= offset)
			{
				new_pos = b->Current - offset;
			}
			else
			{
				new_pos = 0;
			}
		}
	}
	b->Current = MAKESURE(new_pos, 0, b->Size);
}

void SeFreeBufWithoutBuffer(SE_BUF *b)
{
	if (b == NULL)
	{
		return;
	}

	SeFree(b);
}

void SeFreeBuf(SE_BUF *b)
{
	if (b == NULL)
	{
		return;
	}

	SeFree(b->Buf);
	SeFree(b);
}

SE_BUF *SeReadRemainBuf(SE_BUF *b)
{
	UINT size;
	if (b == NULL)
	{
		return NULL;
	}

	if (b->Size < b->Current)
	{
		return NULL;
	}

	size = b->Size - b->Current;

	return SeReadBufFromBuf(b, size);
}

bool SeCmpBuf(SE_BUF *b1, SE_BUF *b2)
{
	if (b1 == NULL || b2 == NULL)
	{
		if (b1 == NULL && b2 == NULL)
		{
			return true;
		}
		else
		{
			return false;
		}
	}

	if (b1->Size != b2->Size)
	{
		return false;
	}

	if (SeCmp(b1->Buf, b2->Buf, b1->Size) != 0)
	{
		return false;
	}

	return true;
}

SE_BUF *SeReadBufFromBuf(SE_BUF *b, UINT size)
{
	SE_BUF *ret;
	UCHAR *data;
	if (b == NULL)
	{
		return NULL;
	}

	data = SeMalloc(size);
	if (SeReadBuf(b, data, size) != size)
	{
		SeFree(data);
		return NULL;
	}

	ret = SeNewBuf();
	SeWriteBuf(ret, data, size);
	SeSeekBuf(ret, 0, 0);

	SeFree(data);

	return ret;
}

void SeWriteBufBuf(SE_BUF *b, SE_BUF *bb)
{
	if (b == NULL || bb == NULL)
	{
		return;
	}

	SeWriteBuf(b, bb->Buf, bb->Size);
}

void SeWriteBufLine(SE_BUF *b, char *str)
{
	char *crlf = "\r\n";
	if (b == NULL || str == NULL)
	{
		return;
	}

	SeWriteBuf(b, str, SeStrLen(str));
	SeWriteBuf(b, crlf, SeStrLen(crlf));
}

void SeWriteBuf(SE_BUF *b, void *buf, UINT size)
{
	UINT new_size;
	if (b == NULL || buf == NULL || size == 0)
	{
		return;
	}

	new_size = b->Current + size;
	if (new_size > b->Size)
	{
		SeAdjustBufSize(b, new_size);
	}
	if (b->Buf != NULL)
	{
		SeCopy((UCHAR *)b->Buf + b->Current, buf, size);
	}
	b->Current += size;
	b->Size = new_size;
}

SE_BUF *SeCloneBuf(SE_BUF *b)
{
	SE_BUF *bb;
	if (b == NULL)
	{
		return NULL;
	}

	bb = SeMemToBuf(b->Buf, b->Size);

	return bb;
}

void SeClearBuf(SE_BUF *b)
{
	if (b == NULL)
	{
		return;
	}

	b->Size = 0;
	b->Current = 0;
}

SE_BUF *SeMemToBuf(void *data, UINT size)
{
	SE_BUF *b;
	if (data == NULL && size != 0)
	{
		return NULL;
	}

	b = SeNewBuf();
	SeWriteBuf(b, data, size);
	SeSeekBuf(b, 0, 0);

	return b;
}

SE_BUF *SeNewBuf()
{
	SE_BUF *b;

	b = SeMalloc(sizeof(SE_BUF));
	b->Buf = SeMalloc(SE_INIT_BUF_SIZE);
	b->Size = 0;
	b->Current = 0;
	b->SizeReserved = SE_INIT_BUF_SIZE;

	return b;
}

UINT64 SeEndian64(UINT64 value)
{
	if (SeIsLittleEndian())
	{
		return SeSwap64(value);
	}
	else
	{
		return value;
	}
}

UINT SeEndian32(UINT value)
{
	if (SeIsLittleEndian())
	{
		return SeSwap32(value);
	}
	else
	{
		return value;
	}
}

USHORT SeEndian16(USHORT value)
{
	if (SeIsLittleEndian())
	{
		return SeSwap16(value);
	}
	else
	{
		return value;
	}
}

void SeSwap(void *buf, UINT size)
{
	UCHAR *tmp, *src;
	UINT i;
	if (buf == NULL || size == 0)
	{
		return;
	}

	src = (UCHAR *)buf;
	tmp = SeMalloc(size);
	for (i = 0;i < size;i++)
	{
		tmp[size - i - 1] = src[i];
	}

	SeCopy(buf, tmp, size);
	SeFree(buf);
}

USHORT SeSwap16(USHORT value)
{
	USHORT r;

	((BYTE *)&r)[0] = ((BYTE *)&value)[1];
	((BYTE *)&r)[1] = ((BYTE *)&value)[0];

	return r;
}

UINT SeSwap32(UINT value)
{
	UINT r;

	((BYTE *)&r)[0] = ((BYTE *)&value)[3];
	((BYTE *)&r)[1] = ((BYTE *)&value)[2];
	((BYTE *)&r)[2] = ((BYTE *)&value)[1];
	((BYTE *)&r)[3] = ((BYTE *)&value)[0];

	return r;
}

UINT64 SeSwap64(UINT64 value)
{
	UINT64 r;

	((BYTE *)&r)[0] = ((BYTE *)&value)[7];
	((BYTE *)&r)[1] = ((BYTE *)&value)[6];
	((BYTE *)&r)[2] = ((BYTE *)&value)[5];
	((BYTE *)&r)[3] = ((BYTE *)&value)[4];
	((BYTE *)&r)[4] = ((BYTE *)&value)[3];
	((BYTE *)&r)[5] = ((BYTE *)&value)[2];
	((BYTE *)&r)[6] = ((BYTE *)&value)[1];
	((BYTE *)&r)[7] = ((BYTE *)&value)[0];

	return r;
}

void *SeClone(void *addr, UINT size)
{
	void *p;
	// 引数チェック
	if (addr == NULL)
	{
		return NULL;
	}

	p = SeMalloc(size);
	SeCopy(p, addr, size);

	return p;
}

void *SeZeroMalloc(UINT size)
{
	void *p = SeMalloc(size);

	if (p == NULL)
	{
		return NULL;
	}

	SeZero(p, size);

	return p;
}

void *SeMalloc(UINT size)
{
	UINT real_size;
	void *p;
	void *ret;

	real_size = size + sizeof(UINT) * 2;

	p = malloc(real_size);

	if (p == NULL)
	{
		SeSysLog(SE_LOG_FATAL, "Memory Allocation Failed.");
		return NULL;
	}

	((UINT *)p)[0] = 0x12345678;
	((UINT *)p)[1] = size;

	ret = (void *)(((UCHAR *)p) + sizeof(UINT) * 2);

	return ret;
}

void SeSysLog(char *type, char *message)
{
	if (type == NULL)
	{
		type = "Info";
	}
	if (message == NULL)
	{
		message = "No Message";
	}

	printf("%s %s\n", type, message);
}

void *SeReAlloc(void *addr, UINT size)
{
	UINT real_size;
	void *real_addr;
	void *p;
	void *ret;
	if (addr == NULL)
	{
		return NULL;
	}

	real_addr = (void *)(((UCHAR *)addr) - sizeof(UINT) * 2);
	real_size = size + sizeof(UINT) * 2;

	if (((UINT *)real_addr)[0] != 0x12345678)
	{
		SeSysLog(SE_LOG_FATAL, "Bad Memory Block.");
		return NULL;
	}

	p = realloc(real_addr, real_size);

	if (p == NULL)
	{
		SeSysLog(SE_LOG_FATAL, "Memory Allocation Failed.");
		return NULL;
	}

	((UINT *)p)[0] = 0x12345678;
	((UINT *)p)[1] = size;

	ret = (void *)(((UCHAR *)p) + sizeof(UINT) * 2);

	return ret;
}

UINT SeMemSize(void *addr)
{
	void *real_addr;
	if (addr == NULL)
	{
		return 0;
	}

	real_addr = (void *)(((UCHAR *)addr) - sizeof(UINT) * 2);

	if (((UINT *)real_addr)[0] != 0x12345678)
	{
		SeSysLog(SE_LOG_FATAL, "Bad Memory Block.");
		return 0;
	}

	return ((UINT *)real_addr)[1];
}

void SeFree(void *addr)
{
	void *real_addr;
	if (addr == NULL)
	{
		return;
	}

	real_addr = (void *)(((UCHAR *)addr) - sizeof(UINT) * 2);

	if (((UINT *)real_addr)[0] != 0x12345678)
	{
		SeSysLog(SE_LOG_FATAL, "Bad Memory Block.");
		return;
	}

	free(real_addr);
}

bool SeIsLittleEndian()
{
	static UINT value = 0x00000001;
	UCHAR *c;

	c = (UCHAR *)value;

	return (c == 0 ? false : true);
}

bool SeIsBigEndian()
{
	return SeIsLittleEndian() ? false : true;
}

bool SeCmpEx(void *addr1, UINT size1, void *addr2, UINT size2)
{
	if (addr1 == NULL || addr2 == NULL)
	{
		return false;
	}

	if (size1 != size2)
	{
		return false;
	}

	if (SeCmp(addr1, addr2, size1) != 0)
	{
		return false;
	}

	return true;
}

int SeCmp(void *addr1, void *addr2, UINT size)
{
	UINT i;
	UCHAR *p1, *p2;
	if (addr1 == NULL || addr2 == NULL || size == 0)
	{
		return 0;
	}

	p1 = (UCHAR *)addr1;
	p2 = (UCHAR *)addr2;

	for (i = 0;i < size;i++)
	{
		if (*p1 > *p2)
		{
			return 1;
		}
		else if (*p1 < *p2)
		{
			return -1;
		}

		p1++;
		p2++;
	}

	return 0;
}

void SeCopy(void *dst, void *src, UINT size)
{
	UINT i;
	UCHAR *p1, *p2;
	if (dst == NULL || src == NULL || size == 0)
	{
		return;
	}

	p1 = (UCHAR *)dst;
	p2 = (UCHAR *)src;

	for (i = 0;i < size;i++)
	{
		*(p1++) = *(p2++);
	}
}

void SeZero(void *addr, UINT size)
{
	UINT i;
	UCHAR *p;
	if (addr == NULL || size == 0)
	{
		return;
	}

	p = (UCHAR *)addr;

	for (i = 0;i < size;i++)
	{
		*(p++) = 0;
	}
}


