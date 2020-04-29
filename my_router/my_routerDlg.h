
// my_routerDlg.h : ͷ�ļ�
//
#include "pcap.h"

#pragma once


#pragma pack(1)  //�ֽڶ���

typedef struct FrameHeader_t{  //֡�ײ�
    BYTE DesMAC[6];  //Ŀ��MAC��ַ
    BYTE SrcMAC[6];  //ԴMAC��ַ
	WORD FrameType;  //֡����
}FrameHeader_t;

typedef struct IPHeader_t{  //IP�ײ�
	BYTE Ver_HLen;  //�汾+ͷ������
    BYTE TOS;  //��������
    WORD TotalLen;  //�ܳ���
    WORD ID;  //��ʶ
    WORD Flag_Segment;  //��־+Ƭƫ��
    BYTE TTL;  //����ʱ��
    BYTE Protocol;  //Э��
    WORD Checksum;  //ͷ��У���
    ULONG SrcIP;  //ԴIP��ַ    
    ULONG DstIP;  //Ŀ��IP��ַ  
}IPHeader_t;

typedef struct Data_t{  //����֡�ײ���IP�ײ������ݰ�
	FrameHeader_t FrameHeader;
	IPHeader_t IPHeader;
}Data_t;

typedef struct ARPFrame_t{  //ARP֡
	FrameHeader_t FrameHeader;   //֡�ײ�
	WORD HardwareType;  //Ӳ������    
	WORD protocolType;  //Э������
	BYTE HLen;  //Ӳ����ַ����
	BYTE PLen;  //Э���ַ����
	WORD Operation;  //����ֵ 
	BYTE SendHa[6];  //ԴMAC��ַ
	DWORD SendIP;  //ԴIP��ַ
	BYTE RecvHa[6];  //Ŀ��MAC��ַ
	DWORD RecvIP;  //Ŀ��IP��ַ
}ARPFrame_t;

typedef struct IP_t{
	DWORD IPAddr;
	DWORD IPNetmask;
}IP_t;

typedef struct ICMPHeader_t{  //ICMP�ײ�
	BYTE Type;  //����
	BYTE Code;  //����
	WORD Checksum;  //У���
	WORD Id;  //��ʶ
	WORD Sequence;  //���к�
}ICMPHeader_t;

typedef struct RouteEntry_t{  //·�ɱ���
	ULONG Mask;  //��������
	ULONG DstIP;  //Ŀ��IP
	ULONG NextHop;  //��һ����
}RouteEntry_t;

typedef struct IPMAC_t{
	ULONG IP;
	BYTE MAC[6];  //MAC��ַ
}IPMAC_t;

typedef struct SendBuff_t{  //���ͻ���
	ULONG DstIP;  //Ŀ��IP
	BYTE PktData[2048];  //��������
}SendBufft_t;

#pragma pack()  //�ָ�Ĭ�϶��뷽ʽ

// Cmy_routerDlg �Ի���
class Cmy_routerDlg : public CDialogEx
{
// ����
public:
	Cmy_routerDlg(CWnd* pParent = NULL);	// ��׼���캯��

// �Ի�������
	enum { IDD = IDD_MY_ROUTER_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV ֧��


// ʵ��
protected:
	HICON m_hIcon;

	// ���ɵ���Ϣӳ�亯��
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()

	pcap_if_t *alldevs;  //ָ���豸�����ײ�ָ��
	pcap_if_t *m_device;
	pcap_addr_t *a;
	pcap_if_t *m_d;  //��ȡ�豸
    bool m_flag;  //��ʼ/ֹͣ�����־

	CWinThread *m_thread;  //�������߳�

	int inum;  //�豸��
	pcap_t *adhandle;  //����ӿڴ�
	struct pcap_pkthdr *pkt_header;
    const u_char* pkt_data;  //����֡�ײ���IP�ײ������ݰ�
	char errbuf[PCAP_ERRBUF_SIZE];  //������Ϣ������
	ARPFrame_t ARPFrame;
	IP_t m_ipaddr1;  //����ip��ַ����������1\2
	IP_t m_ipaddr2;
	BYTE selfmac[6];  //����mac��ַ

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
