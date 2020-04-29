
// my_routerDlg.h : 头文件
//
#include "pcap.h"

#pragma once


#pragma pack(1)  //字节对齐

typedef struct FrameHeader_t{  //帧首部
    BYTE DesMAC[6];  //目的MAC地址
    BYTE SrcMAC[6];  //源MAC地址
	WORD FrameType;  //帧类型
}FrameHeader_t;

typedef struct IPHeader_t{  //IP首部
	BYTE Ver_HLen;  //版本+头部长度
    BYTE TOS;  //服务类型
    WORD TotalLen;  //总长度
    WORD ID;  //标识
    WORD Flag_Segment;  //标志+片偏移
    BYTE TTL;  //生存时间
    BYTE Protocol;  //协议
    WORD Checksum;  //头部校验和
    ULONG SrcIP;  //源IP地址    
    ULONG DstIP;  //目的IP地址  
}IPHeader_t;

typedef struct Data_t{  //包含帧首部和IP首部的数据包
	FrameHeader_t FrameHeader;
	IPHeader_t IPHeader;
}Data_t;

typedef struct ARPFrame_t{  //ARP帧
	FrameHeader_t FrameHeader;   //帧首部
	WORD HardwareType;  //硬件类型    
	WORD protocolType;  //协议类型
	BYTE HLen;  //硬件地址长度
	BYTE PLen;  //协议地址长度
	WORD Operation;  //操作值 
	BYTE SendHa[6];  //源MAC地址
	DWORD SendIP;  //源IP地址
	BYTE RecvHa[6];  //目的MAC地址
	DWORD RecvIP;  //目的IP地址
}ARPFrame_t;

typedef struct IP_t{
	DWORD IPAddr;
	DWORD IPNetmask;
}IP_t;

typedef struct ICMPHeader_t{  //ICMP首部
	BYTE Type;  //类型
	BYTE Code;  //代码
	WORD Checksum;  //校验和
	WORD Id;  //标识
	WORD Sequence;  //序列号
}ICMPHeader_t;

typedef struct RouteEntry_t{  //路由表项
	ULONG Mask;  //子网掩码
	ULONG DstIP;  //目的IP
	ULONG NextHop;  //下一跳步
}RouteEntry_t;

typedef struct IPMAC_t{
	ULONG IP;
	BYTE MAC[6];  //MAC地址
}IPMAC_t;

typedef struct SendBuff_t{  //发送缓存
	ULONG DstIP;  //目的IP
	BYTE PktData[2048];  //缓存数据
}SendBufft_t;

#pragma pack()  //恢复默认对齐方式

// Cmy_routerDlg 对话框
class Cmy_routerDlg : public CDialogEx
{
// 构造
public:
	Cmy_routerDlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
	enum { IDD = IDD_MY_ROUTER_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()

	pcap_if_t *alldevs;  //指向设备链表首部指针
	pcap_if_t *m_device;
	pcap_addr_t *a;
	pcap_if_t *m_d;  //获取设备
    bool m_flag;  //开始/停止捕获标志

	CWinThread *m_thread;  //工作者线程

	int inum;  //设备数
	pcap_t *adhandle;  //网络接口打开
	struct pcap_pkthdr *pkt_header;
    const u_char* pkt_data;  //包含帧首部和IP首部的数据包
	char errbuf[PCAP_ERRBUF_SIZE];  //错误信息缓冲区
	ARPFrame_t ARPFrame;
	IP_t m_ipaddr1;  //本机ip地址与子网掩码1\2
	IP_t m_ipaddr2;
	BYTE selfmac[6];  //本机mac地址

public:
	CString long2ip(DWORD d);
	CString char2mac(BYTE *b);
	void GetselfMac();
	void ARPDeal(struct pcap_pkthdr *pkt_header, const u_char *pkt_data);
	void IPDeal(struct pcap_pkthdr *pkt_header, const u_char *pkt_data);
	void ICMPDeal(BYTE type, BYTE code, const u_char *pkt_data);
	void RouterOn();
	CString m_devname;

	CListBox m_logshow;
	CListBox m_rtrtable;
	CIPAddressCtrl m_mask;
	CIPAddressCtrl m_nexthop;
	CIPAddressCtrl m_dstaddr;
	afx_msg void OnBnClickedAddrtr();
	afx_msg void OnBnClickedDelrtr();
	afx_msg void OnBnClickedBack();
	afx_msg void OnBnClickedStart();
};
