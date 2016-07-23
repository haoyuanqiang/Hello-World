/*
* Copyright (c) 2016,No Corporation
* All rights reserved.
* 
* 文件名称：NetworkInterface.h
* 摘    要：网络接口实现，可实现数据链路层通信
* 
* 当前版本：1.0
* 作    者：ART
* 完成日期：2016年04月07日
* 最后修改日期：2014年04月27日
*
*/
#ifndef __NETWORK_INTERFACE__
#define __NETWORK_INTERFACE__

class HAdapter
{
public:
	LPADAPTER lpAdapter;
	LPPACKET  lpPacket;
	int mode;

	HAdapter()
		:lpAdapter(NULL),
		lpPacket(NULL),
		mode(0)
	{}
};

class ProtocolChannel;

class NetworkInterface
{
private:
    uintptr_t	hThread;    //捕获线程句柄
	//HANDLE	hThread;		
	HWND	hWnd;			//主窗体句柄，用于发送消息
	int		PacketNum;

	HAdapter adapter;

	char AdapterStat;
	
	//设置为0时，表示退出接收线程
	int		RunStatus; 
	DWORD	LastErrCode;
	char	LastErrStr[1024];

	//本地网卡MAC地址
	unsigned char srcMAC[6];
	unsigned char srcIP4[4];

	//网卡列表
	std::vector<Adapter>    AdapterList;

	ProtocolChannel *p;
public:
	HANDLE hEventForRun;
	HANDLE hEventForQuit;
public:
	/*构造和析构函数*/
	NetworkInterface();
	~NetworkInterface();

	//获取错误信息
	DWORD GetErrCode();
	char  *GetErrStr();

	//获取状态：适配器是否打开
	int   GetAdapterStat();

	//获取信息：适配器列表，MAC，IP
	int   GetAdapterList(char AdapterList[10][1024], int &AdapterNum);
	bool  GetMACAddress(LPADAPTER &lpAdapter, u_char *localMAC);
	bool  GetMACAddress(char *AdapterName, u_char *localMAC);
	bool  GetCurrentIP(u_char *MACAddress, u_char *IPV4Address);
	bool  GetCurrentIP();
	int   GetLocalIP(u_char *IP4Address);
	int   GetLocalMAC(u_char *MACAddress);

	//初始化设置函数
	int   InitAdapterCommon(char *adapterName);
	int   SetRecvTimeout(int timeOut); //ms
	int   SetRecvMode(DWORD mode);
	int   SetLocalMAC();
	int   SetHandleInterface(ProtocolChannel *pc);
    int   DelHandleInterface();
	int   ReadyForCapture();

	//关闭适配器，释放接收缓冲区
	void  PacketClose(LPADAPTER &lpAdapter, LPPACKET &lpPacket);

	//发包，收包，分割出单个packet
	int   SendPacket(u_char *buffer, int packetLen, int repeatNum);
	int   CapturePacket();
	void  SplitPackets(LPPACKET &lpPacket);
	

	void  StartRecvPacket();
	void  PauseRecvPacket();
    void  StopRecvPacket();

	void  PrintPacket(u_char *buf, int len, int type);

	//网卡列表处理函数
    int RefreshAdapterList();
	int GetAdapterNum();
	int GetAdapterObj(Adapter &adapter, int adapterIndex);

	//初始化网卡
	int OpenAdapter(int adapterIndex);


};

#endif