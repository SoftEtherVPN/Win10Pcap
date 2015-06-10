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


#ifndef	SETYPES_H
#define	SETYPES_H


#if	!defined(SECRYPTO_C)
typedef struct x509_st X509;
typedef struct evp_pkey_st EVP_PKEY;
typedef struct bio_st BIO;
typedef struct ssl_st SSL;
typedef struct ssl_ctx_st SSL_CTX;
typedef struct X509_req_st X509_REQ;
typedef struct PKCS12 PKCS12;
typedef struct bignum_st BIGNUM;
typedef struct DES_ks DES_key_schedule;
typedef struct dh_st DH;
#endif	// ENCRYPT_C

#ifdef	WIN32
#define SE_STRUCT_PACKED
#define SE_WIN32
#else	// WIN32
#define SE_STRUCT_PACKED	__attribute__ ((__packed__))
#define SE_UNIX
#endif	// WIN32

#define SE_WHERE			{SeDebug("%s: %u", __FILE__, __LINE__);}

#define SE_TIMESPAN(min, sec, millisec)	(((UINT64)(min) * 60ULL + (UINT64)(sec)) * 1000ULL + (UINT64)(millisec))

#ifndef	_WINDOWS_
#define INFINITE			(0xFFFFFFFF)
#define	MAX_PATH			260			
typedef unsigned int		BOOL;
#define TRUE				1
#define FALSE				0
typedef	unsigned int		UINT;
typedef	unsigned int		UINT32;
typedef	unsigned int		DWORD;
typedef	signed int			INT;
typedef	signed int			INT32;
typedef	int					UINT_PTR;
typedef	long				LONG_PTR;
#endif	// _WINDOWS_

#ifndef	NULL
#define NULL				((void *)0)
#endif

#ifndef	WIN32COM_CPP
typedef	unsigned int		bool;
#define	true				1
#define	false				0
#endif	// WIN32COM_CPP

typedef	unsigned short		WORD;
typedef	unsigned short		USHORT;
typedef	signed short		SHORT;
typedef	unsigned char		BYTE;
typedef	unsigned char		UCHAR;

#ifndef	WIN32COM_CPP
typedef signed char			CHAR;
#endif	// WIN32COM_CPP

typedef	unsigned long long	UINT64;
typedef signed long long	INT64;

typedef void *				SE_HANDLE;

#define	STD_SIZE			512
#define	MAX_SIZE			512
#define	BUF_SIZE			512

typedef int (SE_CALLBACK_COMPARE)(void *p1, void *p2);

#ifdef	MAX
#undef	MAX
#endif	// MAX
#ifdef	MIN
#undef	MIN
#endif	// MIN

#define	MIN(a, b)			((a) >= (b) ? (b) : (a))

#define	MAX(a, b)			((a) >= (b) ? (a) : (b))

#define	LESS(a, max_value)	((a) <= (max_value) ? (a) : (max_value))

#define	MORE(a, min_value)	((a) >= (min_value) ? (a) : (min_value))

#define	INNER(a, b, c)		(((b) <= (c) && (a) >= (b) && (a) <= (c)) || ((b) >= (c) && (a) >= (c) && (a) <= (b)))

#define	OUTER(a, b, c)		(!INNER((a), (b), (c)))

#define	MAKESURE(a, b, c)	(((b) <= (c)) ? (MORE(LESS((a), (c)), (b))) : (MORE(LESS((a), (b)), (c))))

#define SE_DEFAULT_VALUE(config_value, default_value)	(((config_value) == 0) ? (default_value) : (config_value))

#define SE_COMPARE(a, b)	(((a) == (b)) ? 0 : (((a) > (b)) ? 1 : -1))

// SeInterface.h
typedef struct SE_SYSCALL_TABLE SE_SYSCALL_TABLE;
typedef struct SE_NICINFO SE_NICINFO;
typedef struct SE_ROOT SE_ROOT;
typedef void (SE_SYS_CALLBACK_TIMER)(SE_HANDLE timer_handle, void *param);
typedef void (SE_SYS_CALLBACK_RECV_NIC)(SE_HANDLE nic_handle, UINT num_packets, void **packets, UINT *packet_sizes, void *param);

// SeKernel.h
typedef struct SE_LOCK SE_LOCK;
typedef struct SE_ETH SE_ETH;
typedef struct SE_TIMER SE_TIMER;
typedef struct SE_TIMER_ENTRY SE_TIMER_ENTRY;
typedef struct SE_ETH_SENDER_MAC SE_ETH_SENDER_MAC;
typedef void (SE_ETH_RECV_CALLBACK)(SE_ETH *eth, void *param);
typedef void (SE_TIMER_CALLBACK)(SE_TIMER *t, UINT64 current_tick, void *param);

// SeMemory.h
typedef struct SE_BUF SE_BUF;
typedef struct SE_FIFO SE_FIFO;
typedef struct SE_LIST SE_LIST;
typedef struct SE_QUEUE SE_QUEUE;
typedef struct SE_STACK SE_STACK;

// SeStr.h
typedef struct SE_TOKEN_LIST SE_TOKEN_LIST;

// SeConfig.h
typedef struct SE_CONFIG_ENTRY SE_CONFIG_ENTRY;

// SeCrypto.h
typedef struct SE_DES_KEY SE_DES_KEY;
typedef struct SE_DES_KEY_VALUE SE_DES_KEY_VALUE;
typedef struct SE_CERT SE_CERT;
typedef struct SE_KEY SE_KEY;
typedef struct SE_DH SE_DH;

// SePacket.h
typedef struct SE_MAC_HEADER SE_MAC_HEADER;
typedef struct SE_ARPV4_HEADER SE_ARPV4_HEADER;
typedef struct SE_IPV4_HEADER SE_IPV4_HEADER;
typedef struct SE_UDP_HEADER SE_UDP_HEADER;
typedef struct SE_UDPV4_PSEUDO_HEADER SE_UDPV4_PSEUDO_HEADER;
typedef struct SE_TCP_HEADER SE_TCP_HEADER;
typedef struct SE_TCPV4_PSEUDO_HEADER SE_TCPV4_PSEUDO_HEADER;
typedef struct SE_ICMP_HEADER SE_ICMP_HEADER;
typedef struct SE_ICMP_ECHO SE_ICMP_ECHO;
typedef struct SE_DHCPV4_HEADER SE_DHCPV4_HEADER;
typedef struct SE_PACKET SE_PACKET;
typedef struct SE_IPV6_HEADER SE_IPV6_HEADER;
typedef struct SE_IPV6_FRAGMENT_HEADER SE_IPV6_FRAGMENT_HEADER;
typedef struct SE_IPV4_ADDR SE_IPV4_ADDR;
typedef struct SE_IPV6_ADDR SE_IPV6_ADDR;
typedef struct SE_IPV6_PSEUDO_HEADER SE_IPV6_PSEUDO_HEADER;
typedef struct SE_IPV6_OPTION_HEADER SE_IPV6_OPTION_HEADER;
typedef struct SE_ICMPV6_OPTION SE_ICMPV6_OPTION;
typedef struct SE_ICMPV6_OPTION_LINK_LAYER SE_ICMPV6_OPTION_LINK_LAYER;
typedef struct SE_ICMPV6_OPTION_PREFIX SE_ICMPV6_OPTION_PREFIX;
typedef struct SE_ICMPV6_OPTION_MTU SE_ICMPV6_OPTION_MTU;
typedef struct SE_ICMPV6_NEIGHBOR_ADVERTISEMENT_HEADER SE_ICMPV6_NEIGHBOR_ADVERTISEMENT_HEADER;
typedef struct SE_ICMPV6_NEIGHBOR_SOLICIATION_HEADER SE_ICMPV6_NEIGHBOR_SOLICIATION_HEADER;
typedef struct SE_ICMPV6_ROUTER_SOLICIATION_HEADER SE_ICMPV6_ROUTER_SOLICIATION_HEADER;
typedef struct SE_ICMPV6_ROUTER_ADVERTISEMENT_HEADER SE_ICMPV6_ROUTER_ADVERTISEMENT_HEADER;
typedef struct SE_ICMPV6_OPTION_LIST SE_ICMPV6_OPTION_LIST;

// SeIp4.h
typedef struct SE_ARPV4_ENTRY SE_ARPV4_ENTRY;
typedef struct SE_ARPV4_WAIT SE_ARPV4_WAIT;
typedef struct SE_IPV4_WAIT SE_IPV4_WAIT;
typedef struct SE_IPV4_FRAGMENT SE_IPV4_FRAGMENT;
typedef struct SE_IPV4_COMBINE SE_IPV4_COMBINE;
typedef struct SE_DHCPV4_OPTION SE_DHCPV4_OPTION;
typedef struct SE_DHCPV4_OPTION_LIST SE_DHCPV4_OPTION_LIST;
typedef struct SE_IPV4 SE_IPV4;
typedef struct SE_IPV4_HEADER_INFO SE_IPV4_HEADER_INFO;
typedef struct SE_UDPV4_HEADER_INFO SE_UDPV4_HEADER_INFO;
typedef struct SE_ICMPV4_HEADER_INFO SE_ICMPV4_HEADER_INFO;
typedef void (SE_IPV4_RECV_CALLBACK)(SE_IPV4 *p, SE_IPV4_HEADER_INFO *info, void *data, UINT size, void *param);

// SeIp6.h
typedef struct SE_IPV6 SE_IPV6;
typedef struct SE_IPV6_HEADER_PACKET_INFO SE_IPV6_HEADER_PACKET_INFO;
typedef struct SE_IPV6_HEADER_INFO SE_IPV6_HEADER_INFO;
typedef struct SE_ICMPV6_HEADER_INFO SE_ICMPV6_HEADER_INFO;
typedef struct SE_UDPV6_HEADER_INFO SE_UDPV6_HEADER_INFO;
typedef struct SE_IPV6_COMBINE SE_IPV6_COMBINE;
typedef struct SE_IPV6_FRAGMENT SE_IPV6_FRAGMENT;
typedef struct SE_IPV6_WAIT SE_IPV6_WAIT;
typedef struct SE_NDPV6_WAIT SE_NDPV6_WAIT;
typedef struct SE_IPV6_NEIGHBOR_ENTRY SE_IPV6_NEIGHBOR_ENTRY;
typedef void (SE_IPV6_RECV_CALLBACK)(SE_IPV6 *p, SE_IPV6_HEADER_INFO *info, void *data, UINT size, void *param);


// SeIke.h
typedef struct SE_IKE_HEADER SE_IKE_HEADER;
typedef struct SE_IKE_PAYLOAD_HEADER SE_IKE_PAYLOAD_HEADER;
typedef struct SE_IKE_COMMON_HEADER SE_IKE_COMMON_HEADER;
typedef struct SE_IKE_PROPOSAL_HEADER SE_IKE_PROPOSAL_HEADER;
typedef struct SE_IKE_TRANSFORM_HEADER SE_IKE_TRANSFORM_HEADER;
typedef struct SE_IKE_TRANSFORM_VALUE SE_IKE_TRANSFORM_VALUE;
typedef struct SE_IKE_ID_HEADER SE_IKE_ID_HEADER;
typedef struct SE_IKE_CERT_HEADER SE_IKE_CERT_HEADER;
typedef struct SE_IKE_CERT_REQUEST_HEADER SE_IKE_CERT_REQUEST_HEADER;
typedef struct SE_IKE_NOTICE_HEADER SE_IKE_NOTICE_HEADER;
typedef struct SE_IKE_SA_HEADER SE_IKE_SA_HEADER;
typedef struct SE_IKE_DELETE_HEADER SE_IKE_DELETE_HEADER;
typedef struct SE_IKE_PACKET SE_IKE_PACKET;
typedef struct SE_IKE_PACKET_PAYLOAD SE_IKE_PACKET_PAYLOAD;
typedef struct SE_IKE_PACKET_SA_PAYLOAD SE_IKE_PACKET_SA_PAYLOAD;
typedef struct SE_IKE_PACKET_PROPOSAL_PAYLOAD SE_IKE_PACKET_PROPOSAL_PAYLOAD;
typedef struct SE_IKE_PACKET_TRANSFORM_PAYLOAD SE_IKE_PACKET_TRANSFORM_PAYLOAD;
typedef struct SE_IKE_PACKET_TRANSFORM_VALUE SE_IKE_PACKET_TRANSFORM_VALUE;
typedef struct SE_IKE_PACKET_ID_PAYLOAD SE_IKE_PACKET_ID_PAYLOAD;
typedef struct SE_IKE_PACKET_CERT_PAYLOAD SE_IKE_PACKET_CERT_PAYLOAD;
typedef struct SE_IKE_PACKET_CERT_REQUEST_PAYLOAD SE_IKE_PACKET_CERT_REQUEST_PAYLOAD;
typedef struct SE_IKE_PACKET_DATA_PAYLOAD SE_IKE_PACKET_DATA_PAYLOAD;
typedef struct SE_IKE_PACKET_NOTICE_PAYLOAD SE_IKE_PACKET_NOTICE_PAYLOAD;
typedef struct SE_IKE_PACKET_DELETE_PAYLOAD SE_IKE_PACKET_DELETE_PAYLOAD;
typedef struct SE_IKE_CRYPTO_PARAM SE_IKE_CRYPTO_PARAM;
typedef struct SE_IKE_IP_ADDR SE_IKE_IP_ADDR;
typedef struct SE_IKE_P1_KEYSET SE_IKE_P1_KEYSET;


// SeSec.h
typedef struct SE_SEC SE_SEC;
typedef struct SE_SEC_CLIENT_FUNCTION_TABLE SE_SEC_CLIENT_FUNCTION_TABLE;
typedef struct SE_SEC_CONFIG SE_SEC_CONFIG;
typedef struct SE_IKE_SA SE_IKE_SA;
typedef struct SE_IPSEC_SA SE_IPSEC_SA;
typedef void (SE_SEC_TIMER_CALLBACK)(UINT64 tick, void *param);
typedef void (SE_SEC_UDP_RECV_CALLBACK)(SE_IKE_IP_ADDR *dest_addr, SE_IKE_IP_ADDR *src_addr, UINT dest_port, UINT src_port, void *data, UINT size, void *param);
typedef void (SE_SEC_ESP_RECV_CALLBACK)(SE_IKE_IP_ADDR *dest_addr, SE_IKE_IP_ADDR *src_addr, void *data, UINT size, void *param);
typedef void (SE_SEC_VIRTUAL_IP_RECV_CALLBACK)(void *data, UINT size, void *param);

// SeVpn.h
typedef struct SE_VPN_CONFIG SE_VPN_CONFIG;
typedef struct SE_VPN SE_VPN;

// SeVpn4.h
typedef struct SE_VPN4 SE_VPN4;

// SeVpn6.h
typedef struct SE_VPN6 SE_VPN6;


#endif	// SETYPES_H

