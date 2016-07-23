/*
* Copyright (c) 2016,No Corporation
* All rights reserved.
* 
* 文件名称：NetworkInterface.cpp
* 摘    要：网络接口实现，可实现数据链路层通信
* 
* 当前版本：1.0
* 作    者：ART
* 完成日期：2016年04月07日
* 最后修改日期：2014年04月27日
*
*/
#include "stdafx.h"
#include <time.h>
#include <stdio.h>
#include <WinSock2.h>
#include <Iphlpapi.h>
#include <iostream>
//-------------------------------------------------------------------------
DWORD WINAPI ThreadProc (PVOID pParam)
{
	NetworkInterface *p = (NetworkInterface *)pParam;
	p->CapturePacket();
	return 0;
}

void ThreadExe(void *pParam)
{
    NetworkInterface *p = (NetworkInterface *)pParam;
	p->CapturePacket();
    _endthread();
}
//-------------------------------------------------------------------------
//构造函数
NetworkInterface::NetworkInterface()
{
	//初始化句柄，避免误用
	hEventForRun = 0;
	hEventForQuit = 0;  //作废
	hThread = 0;
	hWnd = 0;

	PacketNum = 0;
	
	RunStatus  = 1;
	LastErrCode = 0;
	LastErrStr[0] = 0;

	//MAC初始化为00:00:00:00:00:00
	ZeroMemory(srcMAC, 6);
	ZeroMemory(srcIP4, 4);
}

//析构函数
NetworkInterface::~NetworkInterface()
{
	if(AdapterStat == 1)
		PacketClose(adapter.lpAdapter, adapter.lpPacket);
	//ResetEvent(hEventForQuit);
    RunStatus = 0; 
    //Sleep(500);
	//WaitForSingleObject(hEventForQuit, INFINITE);
}

//获取错误代码
DWORD NetworkInterface::GetErrCode()
{
	return LastErrCode;
}

//获取错误信息
char *NetworkInterface::GetErrStr()
{
	return LastErrStr;
}

int NetworkInterface::GetAdapterStat()
{
	return AdapterStat;
}

//获取本机所有网卡的名字
int NetworkInterface::GetAdapterList(char AdapterList[][1024], int &AdapterNum)
{
	//ascii strings
	char AdapterName[8192]; // string that contains a list of the network adapters
	char *temp,*temp1;

	ULONG AdapterLength;

	int i = 0;	

	AdapterLength = sizeof(AdapterName);

	if (PacketGetAdapterNames(AdapterName,&AdapterLength) == FALSE)
	{
		strcpy_s(LastErrStr, "Unable to retrieve the list of the adapters!");
		LastErrCode = GetLastError();
		return -1;
	}

	temp  = AdapterName;
	temp1 = AdapterName;

	while ( (*temp != '\0') || (*(temp-1) != '\0') )
	{
		if (*temp == '\0') 
		{
			memcpy(AdapterList[i], temp1, temp - temp1 + 1);
			temp1 = temp + 1;
			i++;
		}
		temp++;
	}
		  
	AdapterNum = i;	//获取网卡个数
	return 0;
}

//通过打开的适配器句柄获取MAC
bool NetworkInterface::GetMACAddress(LPADAPTER &lpAdapter, u_char *localMAC)
{
	BOOLEAN		Status;
	PPACKET_OID_DATA  OidData;
	
	//分配一个缓冲区来获得MAC地址
	OidData = (PPACKET_OID_DATA)malloc(6 + sizeof(PACKET_OID_DATA));
	if (OidData == NULL) 
	{
		LastErrCode = 3;
		strcpy_s(LastErrStr, "error allocating memory!");
		return false;
	}

	//通过查询NIC驱动取得网卡的MAC地址
	//OID_802_3_PERMANENT_ADDRESS ：物理地址 
	//OID_802_3_CURRENT_ADDRESS   ：mac地址 
	OidData->Oid = OID_802_3_CURRENT_ADDRESS;
	OidData->Length = 6;

	//用0来填充一块内存区域
	ZeroMemory(OidData->Data, 6);
	
	Status = PacketRequest(lpAdapter, FALSE, OidData);
	if(Status)
	{
		for(int i = 0; i < 6; ++i)
			localMAC[i] = (OidData->Data)[i];
	}
	else
	{
		LastErrCode = 4;
		strcpy_s(LastErrStr, "error retrieving the MAC address of the adapter!");
		free(OidData);
		return false;
	}

	free(OidData);
	return true;
}

//通过适配器名字获取MAC地址
bool NetworkInterface::GetMACAddress(char *adapterName, u_char *localMAC)
{
	LPADAPTER lpAdapter = PacketOpenAdapter(adapterName);
	if (!adapter.lpAdapter || (adapter.lpAdapter->hFile == INVALID_HANDLE_VALUE))
	{
		LastErrCode = GetLastError();
		strcpy_s(LastErrStr, "Unable to open the adapter!");
		return false;
	}
	GetMACAddress(lpAdapter, localMAC);
	PacketCloseAdapter(lpAdapter);
	return true;

}

//根据指定MAC地址获得IP地址
bool NetworkInterface::GetCurrentIP(u_char *MACAddress, u_char *IPV4Address)
{
	int flg = 0;
	PIP_ADAPTER_INFO pIpAdapterInfo = new IP_ADAPTER_INFO();
	unsigned long stSize = sizeof(IP_ADAPTER_INFO);

	int nRel = GetAdaptersInfo(pIpAdapterInfo,&stSize);
	if (ERROR_BUFFER_OVERFLOW==nRel)
	{
		//如果函数返回的是ERROR_BUFFER_OVERFLOW
		//则说明GetAdaptersInfo参数传递的内存空间不够,同时其传出stSize,表示需要的空间大小
		delete pIpAdapterInfo;
		pIpAdapterInfo = (PIP_ADAPTER_INFO)new BYTE[stSize];
		nRel=GetAdaptersInfo(pIpAdapterInfo,&stSize); 
	}
	if (ERROR_SUCCESS==nRel)
	{
		PIP_ADAPTER_INFO tpIpAdapterInfo = pIpAdapterInfo;
		while (tpIpAdapterInfo)
		{
			if(memcmp(MACAddress, tpIpAdapterInfo->Address, 6) == 0)
			{
				flg = 1;
				char *pIpAddrString =(tpIpAdapterInfo->IpAddressList.IpAddress.String);
				int i = 0, off = 0;
				while(pIpAddrString[off] != 0)
				{
					if(pIpAddrString[off] == '.')
					{
						i++;
						off++;
						continue;
					}
					IPV4Address[i] = IPV4Address[i] * 10 + pIpAddrString[off] - '0';
					off++;
				}
			}
			tpIpAdapterInfo = tpIpAdapterInfo->Next;
		}
	}
	if(pIpAdapterInfo)
	{
		delete[] pIpAdapterInfo;
	}
	if(flg == 1)
		return true;
	else
		return false;
}

//根据已获取的MAC地址设置IP
bool NetworkInterface::GetCurrentIP()
{
	if(GetCurrentIP(srcMAC, srcIP4))
		return true;
	else
		return false;
}

//获取已打开网卡的IP地址
int NetworkInterface::GetLocalIP(u_char *IP4Address)
{
    u_char IP4[4] = {192,168,1,18};
    memcpy(IP4Address, IP4, 4);
    //memcpy(IP4Address, srcIP4, 4);
	return 0;
}

//获取已打开网卡的MAC地址
int NetworkInterface::GetLocalMAC(u_char *MACAddress)
{
	memcpy(MACAddress, srcMAC, 6);
	return 0;
}

//初始化网卡：打开网卡和初始化包结构
int NetworkInterface::InitAdapterCommon(char *adapterName)
{
	//打开网络网卡
	adapter.lpAdapter = PacketOpenAdapter(adapterName);
	if (!adapter.lpAdapter || (adapter.lpAdapter->hFile == INVALID_HANDLE_VALUE))
	{
		LastErrCode = GetLastError();
		strcpy_s(LastErrStr, "Unable to open the adapter!");
		return -1;
	}
	//分配并初始化一个包结构，将用于接收数据包
	if ((adapter.lpPacket = PacketAllocatePacket()) == NULL)
	{
		LastErrCode = GetLastError();
		strcpy_s(LastErrStr, "Error: failed to allocate the LPPACKET structure.");
		return (-1);
	}
	//此处分配的动态内存在 PacketClose()中释放
	char *buffer = new char[256000];	//256KB
	PacketInitPacket(adapter.lpPacket,(char*)buffer,256000);

	//在驱动中设置512K的缓冲区
	if (PacketSetBuff(adapter.lpAdapter, 512000) == FALSE)
	{
		LastErrCode = GetLastError();
		strcpy_s(LastErrStr, "Unable to set the kernel buffer!");
		return -1;
	}
	AdapterStat = 1;
	return 0;
}

//设置接收Packet超时
int NetworkInterface::SetRecvTimeout(int timeOut) //ms
{
	if (PacketSetReadTimeout(adapter.lpAdapter, timeOut) == FALSE)
	{
		LastErrCode = GetLastError();
		strcpy_s(LastErrStr, "Warning: unable to set the read tiemout!");
		return -1;
	}
	return 0;
}

//设置接收Packet模式
int NetworkInterface::SetRecvMode(DWORD mode)
{
	if (PacketSetHwFilter(adapter.lpAdapter, mode) == FALSE)
	{
		LastErrCode = GetLastError();
		strcpy_s(LastErrStr, "Warning: unable to set promiscuous mode!");
		return -1;
	}
    return 0;
}

//取得已打开网卡的MAC地址
int NetworkInterface::SetLocalMAC()
{
	if( !GetMACAddress(adapter.lpAdapter, srcMAC) )
	{
		LastErrCode = 0x00;
		strcpy_s(LastErrStr, "Failed to Set the MAC Address!");
		return -1;
	}
	return 0;
}

//设置Packet外部处理接口
int NetworkInterface::SetHandleInterface(ProtocolChannel *pc)
{
	p = pc;
	return 0;
}

int NetworkInterface::DelHandleInterface()
{
    //p = NULL;
    return 0;
}

//创建事件和线程
int NetworkInterface::ReadyForCapture()
{
	hEventForRun =  CreateEvent (NULL, TRUE, FALSE, NULL);
	hEventForQuit = CreateEvent (NULL, TRUE, FALSE, NULL);
	//hThread = CreateThread(NULL, 0, ThreadProc, this, 0, NULL);
    hThread = _beginthread(ThreadExe, 0, this);
	RunStatus = 1;
	return 0;
}

//关闭网络网卡
void NetworkInterface::PacketClose(LPADAPTER &lpAdapter, LPPACKET &lpPacket)
{
	//free a PACKET structure
	delete (lpPacket->Buffer);
	lpPacket->Length = 0;
	PacketFreePacket(lpPacket);
	
	//关闭网卡并退出
	PacketCloseAdapter(lpAdapter);
}


//抓包
int NetworkInterface::CapturePacket()
{
	while(1)
	{
		if(!RunStatus)
			break;
		WaitForSingleObject(hEventForRun, INFINITE);
		if (PacketReceivePacket(adapter.lpAdapter, adapter.lpPacket, TRUE) == FALSE)
		{
			LastErrCode = GetLastError();
			strcpy_s(LastErrStr, "Error: PacketReceivePacket failed");
			return (-1);
		}

        if(!RunStatus)
			break;
		/*在此处调用数据包处理函数*/
		SplitPackets(adapter.lpPacket);
	}
	SetEvent(hEventForQuit);
	return 0;
}

//抓包处理函数,解析出单个Packet
void NetworkInterface::SplitPackets(LPPACKET &lpPacket)
{
	ULONG   ulBytesReceived;
	char	*pChar;
	char	*buf;
	u_int   off = 0;

	//caplen为捕获的数据长度，datalen为原始数据长度
	//caplen可能小于datalen
	u_int   caplen, datalen;	
	struct  bpf_hdr *hdr;
	
	//收到的字节数
	ulBytesReceived = lpPacket->ulBytesReceived;

	//缓冲区首地址
	buf = (char*)lpPacket->Buffer;

	//初始化偏移量为0
	off = 0;
	
	while (off < ulBytesReceived)
	{	
		hdr = (struct bpf_hdr *)(buf + off);
		datalen = hdr->bh_datalen;
		caplen  = hdr->bh_caplen;

		//校验捕获的包是否完整,对于不完整的包不做处理
		if(caplen != datalen)
			break;
		off += hdr->bh_hdrlen;

		//单包数据段首地址
		pChar = (char*)(buf + off);

		//跳到下一个包的首地址（可能不存在）
		off = Packet_WORDALIGN(off + caplen);

		//对于自己的Packet不做响应
		if(memcmp((pChar + 6), srcMAC, 6) == 0)
			continue;
		/*在此处处理每个数据包，首地址为pChar,长度为caplen*/
		//在此处调用外部函数处理数据包
		//PrintPacket((u_char*)pChar, caplen, 0);
        if(p != NULL)
		    p->HandlePacket((u_char*)pChar, caplen);	
	}
}

//发包
int NetworkInterface::SendPacket(u_char *buffer, int packetLen, int repeatNum)
{
	
	LPPACKET   lpPacket;

	memcpy((buffer + 6), srcMAC, 6);
	//分配并初始化一个包结构，将用于发送数据包
	if ( (lpPacket = PacketAllocatePacket()) == NULL )
	{
		LastErrCode = GetLastError();
		strcpy_s(LastErrStr, "Error: failed to allocate the LPPACKET structure.");
		return (-1);
	}

	PacketInitPacket(lpPacket, buffer, packetLen);

	if (PacketSetNumWrites(adapter.lpAdapter, repeatNum) == FALSE)
	{
		LastErrCode = GetLastError();
		strcpy_s(LastErrStr, "Unable to send more than one packet in a single write!");
		PacketFreePacket(lpPacket);
		return -1;
	}
	
	if(PacketSendPacket(adapter.lpAdapter, lpPacket, TRUE) == FALSE)
	{
		LastErrCode = GetLastError();
		strcpy_s(LastErrStr, "Error sending the packets!");
		PacketFreePacket(lpPacket);
		return -1;
	}
	PacketFreePacket(lpPacket);
	//将发送的数据包转存到文件中
	//PrintPacket(buffer, packetLen, 1);
	return 0;
}

//开始抓包
void NetworkInterface::StartRecvPacket()
{
	SetEvent(hEventForRun);
}

//暂停抓包
void NetworkInterface::PauseRecvPacket()
{
	ResetEvent(hEventForRun);
}

//停止抓包
void NetworkInterface::StopRecvPacket()
{
    ResetEvent(hEventForQuit);
    RunStatus = 0; 
	WaitForSingleObject(hEventForQuit, INFINITE);
}

//将数据包保存到日志中
void  NetworkInterface::PrintPacket(u_char *buf, int len, int type)
{
	int	i, j, ulLines, ulen, tlen = len;
	u_char	*pChar = buf, *pLine, *base = buf;
	time_t timer;
	tm *ltm;
	if(type == 1)
		freopen("SendLog.txt", "at", stdout);
	else 
		freopen("RecvLog.txt", "at", stdout);

	timer = time(NULL);
	ltm = localtime(&timer);
	printf("Time: %d-%d-%d %d:%d:%d , Length: %d\n", ltm->tm_year + 1900, ltm->tm_mon, ltm->tm_mday, 
		ltm->tm_hour, ltm->tm_min, ltm->tm_sec, len);
	//每行16个数据，求出总共可以排多少行
	ulLines = (tlen + 15) / 16;
		
	for ( i = 0; i < ulLines; i++ )
	{
		pLine = pChar;
		printf( "%08lx : ", pChar-base );
		ulen = tlen;
		ulen = ( ulen > 16 ) ? 16 : ulen;
		tlen -= ulen;
		for ( j = 0; j< ulen; j++ )
			printf( "%02x ", *(BYTE *)pChar++ );

		if ( ulen < 16 )
			printf( "%*s", (16 - ulen) * 3, " " );

		pChar = pLine;

		for ( j = 0; j < ulen; j++, pChar++ )
			printf( "%c", isprint( (u_char)*pChar ) ? *pChar : '.' );

		printf( "\n" );
	} 
	printf( "\n" );
	fclose(stdout);
}

//网卡列表处理函数
int NetworkInterface::RefreshAdapterList()
{
	char AdapterListStr[10][1024];
	int AdapterNum = 10;
	
	GetAdapterList(AdapterListStr, AdapterNum);

	//清除原有的网卡信息
	for(int i = 0; i < AdapterList.size(); ++i)
		FreeAdapter(&(AdapterList[i]));
	AdapterList.clear();
	Adapter adapter;
	for(int i = 0; i < AdapterNum; ++i)
	{
		adapter.AdapterName = new char[strlen(AdapterListStr[i]) + 2];
		strcpy(adapter.AdapterName, AdapterListStr[i]);
		AdapterList.push_back(adapter);
	}
	return 0;
}

//获取本机网卡数目
int NetworkInterface::GetAdapterNum()
{
	return AdapterList.size();
}

//获取指定网卡信息
int NetworkInterface::GetAdapterObj(Adapter &adapter, int adapterIndex)
{
	if(adapterIndex < 0 || adapterIndex >= AdapterList.size())
		return -1;
	adapter = AdapterList[adapterIndex];
	return 0;
}

//打开指定网卡，packet外部处理函数需另外设定
int NetworkInterface::OpenAdapter(int adapterIndex)
{
	if(adapterIndex < 0 || adapterIndex >= AdapterList.size())
	{
		return -1;
	}
	if(GetAdapterStat() == 1)		//如果网卡已打开则不再继续操作
		return 1;
	InitAdapterCommon(AdapterList[adapterIndex].AdapterName);
	SetRecvTimeout(20);
	SetRecvMode(NDIS_PACKET_TYPE_DIRECTED);
	SetLocalMAC();
	GetCurrentIP();
	ReadyForCapture();
	return 0;
}