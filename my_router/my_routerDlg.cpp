
// my_routerDlg.cpp : ʵ���ļ�
//
#include "stdafx.h"
#include <vector>

#include "my_router.h"
#include "my_routerDlg.h"
#include "afxdialogex.h"
#include "pcap.h"



#ifdef _DEBUG
#define new DEBUG_NEW
#endif

CList <SendBuff_t, SendBuff_t&> SP;  //�������ݰ��������
//CList <IPMAC_t, IPMAC_t&> IP_MAC;  //IP-MAC��ַӳ���б�
CList <RouteEntry_t, RouteEntry_t&> RouteTable;  //·�ɱ�
std::vector<IPMAC_t> IP_MAC;

UINT Capturer(LPVOID hWnd);


// ����Ӧ�ó��򡰹��ڡ��˵���� CAboutDlg �Ի���

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// �Ի�������
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

// ʵ��
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// Cmy_routerDlg �Ի���




Cmy_routerDlg::Cmy_routerDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(Cmy_routerDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void Cmy_routerDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LOGSHOW, m_logshow);
	DDX_Control(pDX, IDC_RTRTABLE, m_rtrtable);
	DDX_Control(pDX, IDC_MASK, m_mask);
	DDX_Control(pDX, IDC_NEXTHOP, m_nexthop);
	DDX_Control(pDX, IDC_DSTADDR, m_dstaddr);
}

BEGIN_MESSAGE_MAP(Cmy_routerDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_ADDRTR, &Cmy_routerDlg::OnBnClickedAddrtr)
	ON_BN_CLICKED(IDC_DELRTR, &Cmy_routerDlg::OnBnClickedDelrtr)
	ON_BN_CLICKED(IDC_BACK, &Cmy_routerDlg::OnBnClickedBack)
	ON_BN_CLICKED(IDC_START, &Cmy_routerDlg::OnBnClickedStart)
END_MESSAGE_MAP()


// Cmy_routerDlg ��Ϣ�������

BOOL Cmy_routerDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// ��������...���˵�����ӵ�ϵͳ�˵��С�

	// IDM_ABOUTBOX ������ϵͳ���Χ�ڡ�
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// ���ô˶Ի����ͼ�ꡣ��Ӧ�ó��������ڲ��ǶԻ���ʱ����ܽ��Զ�
	//  ִ�д˲���
	SetIcon(m_hIcon, TRUE);			// ���ô�ͼ��
	SetIcon(m_hIcon, FALSE);		// ����Сͼ��

	// TODO: �ڴ���Ӷ���ĳ�ʼ������
	m_flag = false;
	inum = 0;
	m_d = NULL;
	m_thread = NULL;
	m_devname = "";

	//��ʼ������APRFrame
	ARPFrame.FrameHeader.FrameType = htons(0x0806);
	ARPFrame.HardwareType = htons(0x0001);
	ARPFrame.protocolType = htons(0x0800);
	ARPFrame.HLen = 6;
	ARPFrame.PLen = 4;
	ARPFrame.Operation = htons(0x0001);
	
	for(int i = 0; i < 6; i++)
	{
		ARPFrame.FrameHeader.DesMAC[i] = 0xff;
		ARPFrame.RecvHa[i] = 0x00;
	}

	//��ʼ������MAC
	for(int i = 0; i < 6; i++)
	{
		selfmac[i] = 0x00;
	}

    //��ȡ����������
	if(pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		AfxMessageBox(_T("��ȡʧ�ܣ�"));  //������
		exit(1);
	}
	
	//�������б�ɹ�ѡ��
	for(m_device = alldevs; m_device; m_device = m_device->next)
	{
		inum++;  //�豸����Ŀ
		if(inum != 1)  //1/2
			continue;
		m_d = m_device;
		m_devname = m_device->name;  //����豸��
		if(m_device->description)  //�豸��ϸ��Ϣ
		{
			CString s1(m_device->description);
			m_logshow.AddString(m_devname);  // ��ӵ��б���
			m_logshow.AddString(s1);
		}
		else
			AfxMessageBox(_T("��������"));

		int addrnum = 0;
		for(a = m_device->addresses; a != NULL; a = a->next)
		{
			if(a->addr->sa_family == AF_INET)  //IP��ַ1\2
			{
				if(addrnum == 0)  //IP1
				{
					m_ipaddr1.IPAddr = ntohl(((struct sockaddr_in *)a->addr)->
						sin_addr.S_un.S_addr);  //����a->addr��ȡIP��ַ

					m_ipaddr1.IPNetmask = ntohl(((struct sockaddr_in *)a->netmask)->
						sin_addr.S_un.S_addr);  //����a->netmask��ȡ��������

					DWORD tmpb1 = ntohl(((struct sockaddr_in *)a->broadaddr)->
						sin_addr.S_un.S_addr);  //����a->broadaddr��ȡ�㲥��ַ

					//��ʼ��·�ɱ�
					RouteEntry_t rt;
					//ֱ��Ͷ��·�ɱ������
					rt.Mask = m_ipaddr1.IPNetmask;
					rt.DstIP = m_ipaddr1.IPAddr & m_ipaddr1.IPNetmask;
					rt.NextHop = 0;
					RouteTable.AddHead(rt);
					m_rtrtable.AddString(long2ip(rt.Mask) + " -- " + long2ip(rt.DstIP) + " -- " + long2ip(rt.NextHop) + " (ֱ��Ͷ��)");
					addrnum++;  //IP2
				}
				else if(addrnum == 1)
				{
					m_ipaddr2.IPAddr = ntohl(((struct sockaddr_in *)a->addr)->
						sin_addr.S_un.S_addr);  //����a->addr��ȡIP��ַ

					m_ipaddr2.IPNetmask = ntohl(((struct sockaddr_in *)a->netmask)->
						sin_addr.S_un.S_addr);  //����a->netmask��ȡ��������

					DWORD tmpb2 = ntohl(((struct sockaddr_in *)a->broadaddr)->
						sin_addr.S_un.S_addr);  //����a->broadaddr��ȡ�㲥��ַ

					//��ʼ��·�ɱ�
					RouteEntry_t rt;
					//ֱ��Ͷ��·�ɱ�����ӣ�������
					rt.Mask = m_ipaddr2.IPNetmask;
					rt.DstIP = m_ipaddr2.IPAddr & m_ipaddr2.IPNetmask;
					rt.NextHop = 0;
					RouteTable.AddTail(rt);
					m_rtrtable.AddString(long2ip(rt.Mask) + " -- " + long2ip(rt.DstIP) + " -- " + long2ip(rt.NextHop) + " (ֱ��Ͷ��)");
				}
			}
		}
	}

	if(inum == 0)
	{
		AfxMessageBox(_T("���豸��"));  //û���豸
		return 0;
	}
	m_device = NULL;
	m_devname = "";  //ˢ����0����ʹ��

	if(m_d == NULL)
	{
		AfxMessageBox(_T("���豸��"));
		return 0;
	}

	//������
	if((adhandle = pcap_open_live(m_d->name, 65536, 
		PCAP_OPENFLAG_PROMISCUOUS, 1000, errbuf)) == NULL)
    {
        AfxMessageBox(_T("������ʧ�ܣ�"));
		pcap_freealldevs(alldevs);
        return 0;
    }

	//��ȡ����MAC
	GetselfMac();

	for(int i=0;i<6;i++)  //��ʼ��ARP���󱨵�ԴMAC��ַ��������MAC��ַ
	{
		ARPFrame.FrameHeader.SrcMAC[i] = selfmac[i];
		ARPFrame.SendHa[i] = selfmac[i];
	}

	//����IP����ӵ��б���
	CString mac = char2mac(selfmac);
	CString addr1 = long2ip(m_ipaddr1.IPAddr);
	CString netmask1 = long2ip(m_ipaddr1.IPNetmask);
	m_logshow.AddString(mac);
	m_logshow.AddString(addr1);
	m_logshow.AddString(netmask1);

	CString addr2=long2ip(m_ipaddr2.IPAddr);
	CString netmask2=long2ip(m_ipaddr2.IPNetmask);
	m_logshow.AddString(addr2);
	m_logshow.AddString(netmask2);

	//���ù�����
	CString filt;
	//��̫������MAC��arp��Ӧ����Ŀ��IP��ַ�Ǳ���IP�����ݱ�
	filt = _T("((ether dst " + mac + _T(") and ((arp and (ether[21]=0x2)) or (not (ip dst host ") + addr1 +
		_T(" or ip dst host ") + addr2 + _T("))))"));
	char fil[1000];

	//CStringתChar���飬û�ҵ��ȽϺõķ�ʽ
	int i;
	for(i = 0; i < filt.GetLength(); i++)
	{
		fil[i] = filt[i];
	}
	fil[i] = '\0';
	//USES_CONVERSION;
	//char *a=W2A(filt);


	struct bpf_program filter;
	//������˹���
	if(pcap_compile(adhandle, &filter, fil, 1, htonl(m_ipaddr1.IPNetmask)) < 0)
	{
		MessageBox(_T("���˹������ʧ�ܣ�"));
	}
	//���ù�����
	if(pcap_setfilter(adhandle, &filter) < 0)
	{
		MessageBox(_T("���ù�����ʧ�ܣ�"));
	}

	return TRUE;  // ���ǽ��������õ��ؼ������򷵻� TRUE
}

void Cmy_routerDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// �����Ի��������С����ť������Ҫ����Ĵ���
//  �����Ƹ�ͼ�ꡣ����ʹ���ĵ�/��ͼģ�͵� MFC Ӧ�ó���
//  �⽫�ɿ���Զ���ɡ�

void Cmy_routerDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // ���ڻ��Ƶ��豸������

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// ʹͼ���ڹ����������о���
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// ����ͼ��
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//���û��϶���С������ʱϵͳ���ô˺���ȡ�ù��
//��ʾ��
HCURSOR Cmy_routerDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

//����ͷ��У���     
unsigned short ChecksumCompute(unsigned short *buffer, int size)
{
    //��32λ���м���,������������λ
    unsigned long cksum = 0;
    while(size > 1)
    {
        cksum += *buffer++;  //16λ���
        size -= sizeof(unsigned short);  //ʣ��
	}
    if(size)
    {
        //����������8λ
        cksum += *(unsigned char *)buffer;  //��ʽ
    }
    //��32λcksum�ĸ�16λ��λ������16λ(��λ���ּӵ���λ)
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);
    
    return (unsigned short)(~cksum);  //ȡ����ת����16λ��Ϊ����ֵ����
}  

CString Cmy_routerDlg::long2ip(DWORD d)  //ת��Ϊ���ʮ����
{
	CString ip;
	ip.Format(L"%d.%d.%d.%d",
		(d&0xff000000)>>24,
		(d&0x00ff0000)>>16,
		(d&0x0000ff00)>>8,
		(d&0x000000ff) );

	return ip;
}

CString Cmy_routerDlg::char2mac(BYTE *b)  //MAC��ʽת��
{
	CString mac;
	mac.Format(L"%02X-%02X-%02X-%02X-%02X-%02X",
		b[0]&0xff,
		b[1]&0xff,
		b[2]&0xff,
		b[3]&0xff,
		b[4]&0xff,
		b[5]&0xff	);

	return mac;
}

void Cmy_routerDlg::GetselfMac()  //��ȡ����MAC
{	
	for(int i = 0; i < 6; i++)  //ԴMAC�������
	{
		ARPFrame.FrameHeader.SrcMAC[i] = 0x0f;
		ARPFrame.SendHa[i] = 0x0f;
	}
	ARPFrame.SendIP = inet_addr("100.100.100.100");  //ԴIP�������
	ARPFrame.RecvIP = htonl(m_ipaddr1.IPAddr);  //Ŀ��IP����Ϊ����IP

	if(pcap_sendpacket(adhandle, (u_char *)&ARPFrame, sizeof(ARPFrame_t))!=0)  //�򱾻�����ARP����
	{
		AfxMessageBox(_T("����ʧ�ܣ�"));  //����ʧ��
		return ;
	}
	int res = 0;
	while((res = pcap_next_ex(adhandle, &pkt_header, &pkt_data)) >= 0)  //�������ݱ�
	{
		if(res == 0)
			continue;

		//�����Ӧarp��Ӧ
		if( *(unsigned short *)(pkt_data+12) == htons(0x0806) &&  //ARP
			*(unsigned short *)(pkt_data+20) == htons(0x0002) &&  //Ӧ��
			*(unsigned long *)(pkt_data+38) == inet_addr("100.100.100.100"))
		{
            for(int i = 0; i < 6; i++ )
               selfmac[i]=*(unsigned  char *)(pkt_data+22+i);  //�õ�����MAC��ַ
            break;
		}
	}
}

void Cmy_routerDlg::ARPDeal(struct pcap_pkthdr *pkt_header, const u_char *pkt_data)  //����ARP��
{
	ARPFrame_t *ARPPacket;
	ARPPacket = (ARPFrame_t *)pkt_data;  //ARP���ݰ�

	DWORD sIP;
	sIP = ntohl(ARPPacket->SendIP);  //ARP���ݰ�Դ��ַ��������

	SendBuff_t sPacket;  //���ͻ�����а�
	POSITION ps, CurPos;
	Data_t IPData;  //IP��

	if(ARPPacket->Operation == htons(0x0002))  //ΪARP��Ӧ
	{
		//��־�����Ϣ
		m_logshow.AddString(_T("�յ�ARP(��Ӧ): IP: " + long2ip(sIP) + " MAC: " + char2mac(ARPPacket->SendHa)));
		m_logshow.SetCurSel(m_logshow.GetCount()-1);

		int fl = 0;  //��־
		if(!IP_MAC.empty())  //IP-MAC��Ϊ��
		{
			//IPMAC_t ip_mac;
			//POSITION pos;
			//pos = IP_MAC.GetHeadPosition();  //����IP-MAC��
			for(int i = 0; i < IP_MAC.size(); i++)
			{
				if(IP_MAC[i].IP == sIP)  //IP-MACӳ���Ѵ���
				{
					fl = 1;
					break;
				}
			}
		}
		if(fl == 0)  //�����������IP-MACӳ��
		{
			IPMAC_t tmp;
			tmp.IP = sIP;
			for(int i = 0; i < 6; i++ )
               tmp.MAC[i] = ARPPacket->SendHa[i];
			IP_MAC.push_back(tmp);  //��ӵ�IPMAC��
			m_logshow.AddString(_T("IP-MACӳ������: IP: " + long2ip(tmp.IP) + " -- MAC: " + char2mac(tmp.MAC)));
			m_logshow.SetCurSel(m_logshow.GetCount()-1);
		}
		//�յ���Ӧ�������ؿ�����ͼ�������ݱ�����黺��
		fl = 0;  //��־����
		while(fl == 0)  //�����ж�����ĵȴ�ת��
		{
			if(SP.IsEmpty())  //�������Ϊ��
			{
				return ;
			}
			//�������д��������ݱ����鷢��
			
			ps = SP.GetHeadPosition();
			for(int i = 0; i < SP.GetCount(); i++)  //��������
			{
				CurPos = ps;
				sPacket = SP.GetNext(ps);
				
				DWORD MaxMask = 0;  //��ȡ�����������ĵ�ַ���ƥ��
				int fl = -1;  //��־
				DWORD tmp;
				POSITION pos;
				RouteEntry_t rt;

				pos = RouteTable.GetHeadPosition();
				for (int i = 0; i < RouteTable.GetCount(); i++)  //����·�ɱ�(������)
				{
					rt = RouteTable.GetNext(pos);
					if ((ntohl(sPacket.DstIP) & rt.Mask) == rt.DstIP)  //�ҵ���Ӧ·��
					{
						fl = i;
						if (rt.Mask >= MaxMask)  //�ƥ�䣬1���
						{
							if (rt.NextHop == 0)  //ֱ��Ͷ��
								tmp = ntohl(sPacket.DstIP);
							else
								tmp = rt.NextHop;  //�ҵ���һ��
							MaxMask = rt.Mask;  //�����
						}
					}
				}
				if (fl != -1)  //�ҵ�
				{
					if (tmp == ntohl(ARPPacket->SendIP))  //����������з�����IP��ַ�ı�
					{
						memcpy(&IPData, SP.GetNext(ps).PktData, sizeof(Data_t));
						for (int j = 0; j < 6; j++)
						{
							IPData.FrameHeader.DesMAC[j] = ARPPacket->SendHa[j];  //Ŀ��MAC����Ϊ�յ���ARP����Դ��ַ
							IPData.FrameHeader.SrcMAC[j] = selfmac[j];  //ԴMAC����Ϊ����MAC
						}
					}
				}
				//����IP���ݰ�
				if(pcap_sendpacket(adhandle, (u_char *)&IPData, sizeof(Data_t))!=0)
				{
					AfxMessageBox(_T("����IP���ݱ�ʧ�ܣ�"));
					return ;
				}
				SP.RemoveAt(CurPos);
				//��־���
				m_logshow.AddString(_T("ת��IP���ݱ���" + long2ip(ntohl(IPData.IPHeader.SrcIP)) + " --> " + long2ip(ntohl(IPData.IPHeader.DstIP))
					+ " , " + char2mac(IPData.FrameHeader.SrcMAC) + " --> " + char2mac(IPData.FrameHeader.DesMAC)));
				m_logshow.SetCurSel(m_logshow.GetCount()-1);
				break;
			}
			fl = 1;  //û�д�ת�����ݰ���
		}
	}
}

void Cmy_routerDlg::ICMPDeal(BYTE type, BYTE code, const u_char *pkt_data)  //ICMP���ݰ�
{
	m_logshow.AddString(_T("icmpDeal"));
}

void Cmy_routerDlg::IPDeal(struct pcap_pkthdr *pkt_header, const u_char *pkt_data)  //IP���Ĵ���
{
	//����IP���ݰ�
	Data_t *IPPacket;
	IPPacket = (Data_t *)pkt_data;
	int length = pkt_header->len;

	WORD RecvChecksum;  //�յ���У���
	WORD CkChecksum;  //У��ͼ��
	SendBuff_t sb;  //���汨

	//�����־
	m_logshow.AddString(_T("�յ�IP���ݱ�: " + long2ip(ntohl(IPPacket->IPHeader.SrcIP)) + " --> " + long2ip(ntohl(IPPacket->IPHeader.DstIP))));
	m_logshow.SetCurSel(m_logshow.GetCount()-1);

	if(IPPacket->IPHeader.TTL <= 0)
	{
		ICMPDeal(11, 0, pkt_data);  //ICMP���󱨸棺��ʱ
		return ;
	}

	//int flag = 0;
	////��ѯIP-MACӳ���
	//if (!IP_MAC.empty())  //��Ϊ��
	//{
	//	//IPMAC_t ip_mac;
	//	//POSITION pos;
	//	//pos = IP_MAC.GetHeadPosition();
	//	for (int i = 0; i < IP_MAC.size(); i++)  //����IP-MACӳ���������
	//	{
	//		//ip_mac = IP_MAC.GetNext(pos);
	//		if (ntohl(IPPacket->IPHeader.SrcIP) == IP_MAC[i].IP)  //IP-MACӳ���Ѵ���
	//		{
	//			flag = 1;
	//			break;
	//		}
	//	}
	//}
	//if (flag == 0)
	//{
	//	IPMAC_t ip_mac;
	//	ip_mac.IP = ntohl(IPPacket->IPHeader.SrcIP);
	//	memcpy(ip_mac.MAC,IPPacket->FrameHeader.SrcMAC,6);

	//	IP_MAC.push_back(ip_mac);
	//	m_logshow.AddString(_T("δ�ҵ�IP-MACӳ���ϵ�����뻺������" + long2ip(ntohl(IPPacket->IPHeader.SrcIP)) + " --> "
	//		+ char2mac(IPPacket->FrameHeader.SrcMAC)));
	//}

	RecvChecksum = IPPacket->IPHeader.Checksum;

	IPPacket->IPHeader.Checksum = 0;  //��IPͷ�е�У���Ϊ0
	unsigned short check_buff[sizeof(IPHeader_t)];
	memset(check_buff, 0, sizeof(IPHeader_t));
	IPHeader_t *ip_header = &(IPPacket->IPHeader); 
	memcpy(check_buff, ip_header, sizeof(IPHeader_t));

	//���¼���IPͷ��У���
	IPPacket->IPHeader.Checksum = ChecksumCompute(check_buff, sizeof(IPHeader_t));
	CkChecksum = IPPacket->IPHeader.Checksum;

	if(RecvChecksum != CkChecksum)  //ͷ��У�����
	{
		m_logshow.AddString(_T("IP���ݰ�У��ʹ��󣬶���"));
		m_logshow.SetCurSel(m_logshow.GetCount()-1);
		return ;
	}

	DWORD tmp;
	DWORD MaxMask = 0;  //��ȡ�����������ĵ�ַ���ƥ��
	int fl = -1;  //��־
	
	POSITION pos;
	RouteEntry_t rt;

	pos = RouteTable.GetHeadPosition();
	for(int i = 0; i < RouteTable.GetCount(); i++)  //����·�ɱ�(������)
	{
		rt = RouteTable.GetNext(pos);
		if((ntohl(IPPacket->IPHeader.DstIP) & rt.Mask) == rt.DstIP)  //�ҵ���Ӧ·��
		{
			fl = i;
			if(rt.Mask >= MaxMask)  //�ƥ�䣬1���
			{
				if(rt.NextHop == 0)  //ֱ��Ͷ��
					tmp = ntohl(IPPacket->IPHeader.DstIP);
				else
					tmp = rt.NextHop;  //�ҵ���һ��
				MaxMask = rt.Mask;  //�����
			}
		}
	}
	if(fl == -1)  //û�ҵ�
	{
		ICMPDeal(3, 0, pkt_data);  //ICMP���󱨸棺Ŀ�Ĳ��ɴ�
		return ;
	}
	else
	{
		sb.DstIP = tmp;  //�ҵ�����һ��ַ��������������ݰ���sb
		memcpy(IPPacket->FrameHeader.SrcMAC, selfmac, 6);  //ԴMAC��Ϊ����MAC
		IPPacket->IPHeader.TTL -= 1;  //TTL��1
		memcpy(sb.PktData, pkt_data, sizeof(Data_t));  //�������ݰ�
		IPPacket->IPHeader.Checksum = 0;  //��IPͷ�е�У���Ϊ0
		unsigned short check_buff[sizeof(IPHeader_t)];
		memset(check_buff, 0, sizeof(IPHeader_t));
		IPHeader_t *ip_header = &(IPPacket->IPHeader);
		memcpy(check_buff, ip_header, sizeof(IPHeader_t));
		//���¼���IPͷ��У���
		IPPacket->IPHeader.Checksum = ChecksumCompute(check_buff, sizeof(IPHeader_t));

		//��ѯIP-MACӳ���
		int fla = 0;  //��־
		if(!IP_MAC.empty())  //��Ϊ��
		{

			//IPMAC_t ip_mac;
			//POSITION pos;
			//pos = IP_MAC.GetHeadPosition();
			for(int i = 0; i < IP_MAC.size(); i++)  //����IP-MACӳ���������
			{
				//ip_mac = IP_MAC.GetAt(pos);
				if(sb.DstIP == IP_MAC[i].IP)  //IP-MACӳ���Ѵ���
				{
					for(int j = 0; j < 6; j++)
					{
						IPPacket->FrameHeader.DesMAC[j] = IP_MAC[i].MAC[j];
					}
					fla = 1;
					break;
				}
				pos++;
			}


		}
		if (fla == 1)  //�ҵ�ӳ��ֱ�ӷ�
		{
			if (pcap_sendpacket(adhandle, (u_char *)IPPacket, length) != 0)
			{
				AfxMessageBox(_T("����IP���ݰ�ʧ��!"));
				return;
			}

			//�����־
			m_logshow.AddString(_T("ת��IP���ݱ�: " + long2ip(ntohl(IPPacket->IPHeader.SrcIP)) + " --> " + long2ip(ntohl(IPPacket->IPHeader.DstIP)) + " , " + char2mac(IPPacket->FrameHeader.SrcMAC) + " --> " + char2mac(IPPacket->FrameHeader.DesMAC)));
			m_logshow.SetCurSel(m_logshow.GetCount() - 1);
			return;
		}
		else//δ�ҵ�IP-MACӳ���ϵ
		{
			if(SP.GetCount() < 65535)  //����
			{
				SP.AddTail(sb);  //���뻺�����
				
				//�����־

				m_logshow.SetCurSel(m_logshow.GetCount()-1);
				m_logshow.AddString(_T("����ARP����")+ long2ip(sb.DstIP));
				m_logshow.SetCurSel(m_logshow.GetCount()-1);

				//ARP����
				DWORD sendip = m_ipaddr2.IPAddr;
				ARPFrame.SendIP = htonl(sendip);
				DWORD recvip = htonl(sb.DstIP);
				ARPFrame.RecvIP = recvip;
				//����ARP����
				if(pcap_sendpacket(adhandle,(u_char *)&ARPFrame, sizeof(ARPFrame_t))!=0)
				{
					AfxMessageBox(_T("����ARP���ݰ�ʧ��!"));
					return ;
				}
			}
			else  //���Ĺ��࣬����
			{
				m_logshow.AddString(_T("��������������������ݰ���" + long2ip(ntohl(IPPacket->IPHeader.SrcIP)) + " --> " + long2ip(ntohl(IPPacket->IPHeader.DstIP))));
				m_logshow.SetCurSel(m_logshow.GetCount()-1);
			}
		}
	}
}

void Cmy_routerDlg::RouterOn()  //·�ɿ���
{
	int res = 0;

	while((res = pcap_next_ex(adhandle, &pkt_header, &pkt_data)) >= 0)
	{
		if(m_flag == false)  //ֹͣץ�����ر�·��
			break ;
		if(res == 0)
		{
			m_logshow.AddString(L"time out.");  //��ʱ
			m_logshow.SetCurSel(m_logshow.GetCount()-1);
			continue;
		}
		FrameHeader_t *fh;
		fh = (FrameHeader_t *)pkt_data;
		if(ntohs(fh->FrameType)==0x0806)  //ARP
		{
			ARPDeal(pkt_header, pkt_data);  //����ARP����
		}
		else if(ntohs(fh->FrameType)==0x0800)  //IP
		{
			IPDeal(pkt_header, pkt_data);  //����IP����
		}
	}
	//pcap_close(adhandle);
	//�ͷ��豸�б�
	pcap_freealldevs(alldevs);
	return ;
}



void Cmy_routerDlg::OnBnClickedAddrtr()  //���·�ɱ���
{
	// TODO:  �ڴ���ӿؼ�֪ͨ����������
	DWORD ipaddr;
	RouteEntry_t rt;
	POSITION pos, CurrentPos;
	//��һ����
	m_nexthop.GetAddress(ipaddr);
	rt.NextHop = ipaddr;
	//Ŀ��IP
	m_dstaddr.GetAddress(ipaddr);
	rt.DstIP = ipaddr;
	//��������
	m_mask.GetAddress(ipaddr);
	rt.Mask = ipaddr;
	
	RouteEntry_t rtmp;
	pos = RouteTable.GetHeadPosition();
	for(int i = 0; i < RouteTable.GetCount(); i++)  //�����·�ɱ����Ѿ�����
	{
		CurrentPos = pos;
		rtmp = RouteTable.GetNext(pos);
		if ((rt.Mask == rtmp.Mask) && (rt.DstIP == rtmp.DstIP) && (rt.NextHop == rtmp.NextHop))
		{
			MessageBox(_T("�Ѿ����ڣ�"));
			return ;
		}
	}
	//������
	if(((m_ipaddr1.IPNetmask) & rt.NextHop) == ((m_ipaddr1.IPNetmask) & m_ipaddr1.IPAddr)
		||((m_ipaddr2.IPNetmask) & rt.NextHop) == ((m_ipaddr2.IPNetmask) & m_ipaddr2.IPAddr))  //�ж��ܷ񵽴�
	{
		//��ӵ�·�ɱ�
		RouteTable.AddTail(rt);
		//��ʾ
		m_rtrtable.AddString(long2ip(rt.Mask) + " -- " + 
			long2ip(rt.DstIP) + " -- " + long2ip(rt.NextHop));
	}
	else
	{
		MessageBox(_T("�������"));
	}
	// TODO: �ڴ���ӿؼ�֪ͨ����������
}


void Cmy_routerDlg::OnBnClickedDelrtr()  //ɾ��·�ɱ���
{
	// TODO:  �ڴ���ӿؼ�֪ͨ����������
	DWORD ipaddr;
	RouteEntry_t rt;
	POSITION pos, CurrentPos, p;
	//��һ����
	m_nexthop.GetAddress(ipaddr);
	rt.NextHop = ipaddr;
	//Ŀ��IP
	m_dstaddr.GetAddress(ipaddr);
	rt.DstIP = ipaddr;
	//��������
	m_mask.GetAddress(ipaddr);
	rt.Mask = ipaddr;

	if(rt.NextHop == 0)  //ֱ������
	{
		MessageBox(_T("ֱ������·�ɣ�ɾ��ʧ�ܣ�"));
		return;
	}

	//����·�ɱ�ɾ��·�ɱ���
	int fl = 0;
	RouteEntry_t rtmp;
	pos = RouteTable.GetHeadPosition();
	for(int i = 0; i < RouteTable.GetCount(); i++)
	{
		CurrentPos = pos;
		rtmp = RouteTable.GetNext(pos);
		if ((rt.Mask == rtmp.Mask) && (rt.DstIP == rtmp.DstIP) && (rt.NextHop == rtmp.NextHop))
		{
			RouteTable.RemoveAt(CurrentPos);
			fl = 1;  //��־�ҵ�
			break ;
		}
	}
	if(fl == 0)
	{
		MessageBox(_T("���޴��ɾ��ʧ�ܣ�"));
		return ;
	}
	m_rtrtable.ResetContent();  //��ʾ�б�����
	p = RouteTable.GetHeadPosition();
	for(int i = 0; i < RouteTable.GetCount(); i++)
	{
		rtmp = RouteTable.GetNext(p);
		if(rtmp.NextHop == 0)  //ֱ��Ͷ��
			m_rtrtable.AddString(long2ip(rtmp.Mask) + " -- " + long2ip(rtmp.DstIP) + " -- " + long2ip(rtmp.NextHop) + " (ֱ��Ͷ��)");
		else
			m_rtrtable.AddString(long2ip(rtmp.Mask) + " -- " + long2ip(rtmp.DstIP) + " -- " + long2ip(rtmp.NextHop));
	}
}


void Cmy_routerDlg::OnBnClickedBack()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	m_logshow.ResetContent();  //�����־

}


UINT Capturer(LPVOID hWnd)
{
	Cmy_routerDlg *pDlg = (Cmy_routerDlg *)hWnd;
	pDlg->RouterOn();  //·�ɿ���

    return 1;
}


void Cmy_routerDlg::OnBnClickedStart()
{
	if(m_flag == true)  //ֹͣ����
	{
		m_flag = false;
		m_logshow.AddString(_T("·�ɹرա�"));
		m_logshow.SetCurSel(m_logshow.GetCount()-1);
	}
	else  //��ʼ����
	{
		m_flag = true;
		m_logshow.AddString(_T("·�ɴ򿪡�"));
		m_logshow.SetCurSel(m_logshow.GetCount()-1);
		//�����߳̿�ʼץ��
		m_thread = AfxBeginThread(Capturer,this,THREAD_PRIORITY_NORMAL);
	}
	// TODO: �ڴ���ӿؼ�֪ͨ����������
}
