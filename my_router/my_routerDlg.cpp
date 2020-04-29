
// my_routerDlg.cpp : 实现文件
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

CList <SendBuff_t, SendBuff_t&> SP;  //发送数据包缓存队列
//CList <IPMAC_t, IPMAC_t&> IP_MAC;  //IP-MAC地址映射列表
CList <RouteEntry_t, RouteEntry_t&> RouteTable;  //路由表
std::vector<IPMAC_t> IP_MAC;

UINT Capturer(LPVOID hWnd);


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
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


// Cmy_routerDlg 对话框




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


// Cmy_routerDlg 消息处理程序

BOOL Cmy_routerDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
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

	// 设置此对话框的图标。当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码
	m_flag = false;
	inum = 0;
	m_d = NULL;
	m_thread = NULL;
	m_devname = "";

	//初始化部分APRFrame
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

	//初始化自身MAC
	for(int i = 0; i < 6; i++)
	{
		selfmac[i] = 0x00;
	}

    //获取网络适配器
	if(pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		AfxMessageBox(_T("获取失败！"));  //错误处理
		exit(1);
	}
	
	//适配器列表可供选择
	for(m_device = alldevs; m_device; m_device = m_device->next)
	{
		inum++;  //设备器数目
		if(inum != 1)  //1/2
			continue;
		m_d = m_device;
		m_devname = m_device->name;  //获得设备名
		if(m_device->description)  //设备详细信息
		{
			CString s1(m_device->description);
			m_logshow.AddString(m_devname);  // 添加到列表项
			m_logshow.AddString(s1);
		}
		else
			AfxMessageBox(_T("无描述！"));

		int addrnum = 0;
		for(a = m_device->addresses; a != NULL; a = a->next)
		{
			if(a->addr->sa_family == AF_INET)  //IP地址1\2
			{
				if(addrnum == 0)  //IP1
				{
					m_ipaddr1.IPAddr = ntohl(((struct sockaddr_in *)a->addr)->
						sin_addr.S_un.S_addr);  //利用a->addr获取IP地址

					m_ipaddr1.IPNetmask = ntohl(((struct sockaddr_in *)a->netmask)->
						sin_addr.S_un.S_addr);  //利用a->netmask获取网络掩码

					DWORD tmpb1 = ntohl(((struct sockaddr_in *)a->broadaddr)->
						sin_addr.S_un.S_addr);  //利用a->broadaddr获取广播地址

					//初始化路由表
					RouteEntry_t rt;
					//直接投递路由表项添加
					rt.Mask = m_ipaddr1.IPNetmask;
					rt.DstIP = m_ipaddr1.IPAddr & m_ipaddr1.IPNetmask;
					rt.NextHop = 0;
					RouteTable.AddHead(rt);
					m_rtrtable.AddString(long2ip(rt.Mask) + " -- " + long2ip(rt.DstIP) + " -- " + long2ip(rt.NextHop) + " (直接投递)");
					addrnum++;  //IP2
				}
				else if(addrnum == 1)
				{
					m_ipaddr2.IPAddr = ntohl(((struct sockaddr_in *)a->addr)->
						sin_addr.S_un.S_addr);  //利用a->addr获取IP地址

					m_ipaddr2.IPNetmask = ntohl(((struct sockaddr_in *)a->netmask)->
						sin_addr.S_un.S_addr);  //利用a->netmask获取网络掩码

					DWORD tmpb2 = ntohl(((struct sockaddr_in *)a->broadaddr)->
						sin_addr.S_un.S_addr);  //利用a->broadaddr获取广播地址

					//初始化路由表
					RouteEntry_t rt;
					//直接投递路由表项添加，主机序
					rt.Mask = m_ipaddr2.IPNetmask;
					rt.DstIP = m_ipaddr2.IPAddr & m_ipaddr2.IPNetmask;
					rt.NextHop = 0;
					RouteTable.AddTail(rt);
					m_rtrtable.AddString(long2ip(rt.Mask) + " -- " + long2ip(rt.DstIP) + " -- " + long2ip(rt.NextHop) + " (直接投递)");
				}
			}
		}
	}

	if(inum == 0)
	{
		AfxMessageBox(_T("无设备！"));  //没有设备
		return 0;
	}
	m_device = NULL;
	m_devname = "";  //刷新置0后续使用

	if(m_d == NULL)
	{
		AfxMessageBox(_T("无设备！"));
		return 0;
	}

	//打开网卡
	if((adhandle = pcap_open_live(m_d->name, 65536, 
		PCAP_OPENFLAG_PROMISCUOUS, 1000, errbuf)) == NULL)
    {
        AfxMessageBox(_T("打开网卡失败！"));
		pcap_freealldevs(alldevs);
        return 0;
    }

	//获取自身MAC
	GetselfMac();

	for(int i=0;i<6;i++)  //初始化ARP请求报的源MAC地址换成自身MAC地址
	{
		ARPFrame.FrameHeader.SrcMAC[i] = selfmac[i];
		ARPFrame.SendHa[i] = selfmac[i];
	}

	//本机IP等添加到列表项
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

	//设置过滤器
	CString filt;
	//以太网本机MAC，arp响应或者目的IP地址非本机IP的数据报
	filt = _T("((ether dst " + mac + _T(") and ((arp and (ether[21]=0x2)) or (not (ip dst host ") + addr1 +
		_T(" or ip dst host ") + addr2 + _T("))))"));
	char fil[1000];

	//CString转Char数组，没找到比较好的方式
	int i;
	for(i = 0; i < filt.GetLength(); i++)
	{
		fil[i] = filt[i];
	}
	fil[i] = '\0';
	//USES_CONVERSION;
	//char *a=W2A(filt);


	struct bpf_program filter;
	//编译过滤规则
	if(pcap_compile(adhandle, &filter, fil, 1, htonl(m_ipaddr1.IPNetmask)) < 0)
	{
		MessageBox(_T("过滤规则编译失败！"));
	}
	//设置过滤器
	if(pcap_setfilter(adhandle, &filter) < 0)
	{
		MessageBox(_T("设置过滤器失败！"));
	}

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
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

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void Cmy_routerDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR Cmy_routerDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

//计算头部校验和     
unsigned short ChecksumCompute(unsigned short *buffer, int size)
{
    //用32位进行计算,方便后续处理进位
    unsigned long cksum = 0;
    while(size > 1)
    {
        cksum += *buffer++;  //16位相加
        size -= sizeof(unsigned short);  //剩余
	}
    if(size)
    {
        //最后如果还有8位
        cksum += *(unsigned char *)buffer;  //格式
    }
    //将32位cksum的高16位进位加至低16位(进位部分加到低位)
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);
    
    return (unsigned short)(~cksum);  //取反并转换成16位作为最终值返回
}  

CString Cmy_routerDlg::long2ip(DWORD d)  //转换为点分十进制
{
	CString ip;
	ip.Format(L"%d.%d.%d.%d",
		(d&0xff000000)>>24,
		(d&0x00ff0000)>>16,
		(d&0x0000ff00)>>8,
		(d&0x000000ff) );

	return ip;
}

CString Cmy_routerDlg::char2mac(BYTE *b)  //MAC格式转换
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

void Cmy_routerDlg::GetselfMac()  //获取本机MAC
{	
	for(int i = 0; i < 6; i++)  //源MAC虚假设置
	{
		ARPFrame.FrameHeader.SrcMAC[i] = 0x0f;
		ARPFrame.SendHa[i] = 0x0f;
	}
	ARPFrame.SendIP = inet_addr("100.100.100.100");  //源IP虚假设置
	ARPFrame.RecvIP = htonl(m_ipaddr1.IPAddr);  //目的IP设置为本机IP

	if(pcap_sendpacket(adhandle, (u_char *)&ARPFrame, sizeof(ARPFrame_t))!=0)  //向本机发送ARP请求
	{
		AfxMessageBox(_T("发送失败！"));  //发送失败
		return ;
	}
	int res = 0;
	while((res = pcap_next_ex(adhandle, &pkt_header, &pkt_data)) >= 0)  //捕获数据报
	{
		if(res == 0)
			continue;

		//捕获对应arp响应
		if( *(unsigned short *)(pkt_data+12) == htons(0x0806) &&  //ARP
			*(unsigned short *)(pkt_data+20) == htons(0x0002) &&  //应答
			*(unsigned long *)(pkt_data+38) == inet_addr("100.100.100.100"))
		{
            for(int i = 0; i < 6; i++ )
               selfmac[i]=*(unsigned  char *)(pkt_data+22+i);  //得到本机MAC地址
            break;
		}
	}
}

void Cmy_routerDlg::ARPDeal(struct pcap_pkthdr *pkt_header, const u_char *pkt_data)  //处理ARP包
{
	ARPFrame_t *ARPPacket;
	ARPPacket = (ARPFrame_t *)pkt_data;  //ARP数据包

	DWORD sIP;
	sIP = ntohl(ARPPacket->SendIP);  //ARP数据包源地址，主机序

	SendBuff_t sPacket;  //发送缓存队列包
	POSITION ps, CurPos;
	Data_t IPData;  //IP报

	if(ARPPacket->Operation == htons(0x0002))  //为ARP响应
	{
		//日志输出信息
		m_logshow.AddString(_T("收到ARP(响应): IP: " + long2ip(sIP) + " MAC: " + char2mac(ARPPacket->SendHa)));
		m_logshow.SetCurSel(m_logshow.GetCount()-1);

		int fl = 0;  //标志
		if(!IP_MAC.empty())  //IP-MAC表不为空
		{
			//IPMAC_t ip_mac;
			//POSITION pos;
			//pos = IP_MAC.GetHeadPosition();  //遍历IP-MAC表
			for(int i = 0; i < IP_MAC.size(); i++)
			{
				if(IP_MAC[i].IP == sIP)  //IP-MAC映射已存在
				{
					fl = 1;
					break;
				}
			}
		}
		if(fl == 0)  //不存在则添加IP-MAC映射
		{
			IPMAC_t tmp;
			tmp.IP = sIP;
			for(int i = 0; i < 6; i++ )
               tmp.MAC[i] = ARPPacket->SendHa[i];
			IP_MAC.push_back(tmp);  //添加到IPMAC表
			m_logshow.AddString(_T("IP-MAC映射表添加: IP: " + long2ip(tmp.IP) + " -- MAC: " + char2mac(tmp.MAC)));
			m_logshow.SetCurSel(m_logshow.GetCount()-1);
		}
		//收到响应包代表本地可能试图发送数据报，检查缓存
		fl = 0;  //标志重置
		while(fl == 0)  //可能有多个报文等待转发
		{
			if(SP.IsEmpty())  //缓存队列为空
			{
				return ;
			}
			//缓存中有待发送数据报则检查发送
			
			ps = SP.GetHeadPosition();
			for(int i = 0; i < SP.GetCount(); i++)  //遍历缓存
			{
				CurPos = ps;
				sPacket = SP.GetNext(ps);
				
				DWORD MaxMask = 0;  //获取最大子网掩码的地址，最长匹配
				int fl = -1;  //标志
				DWORD tmp;
				POSITION pos;
				RouteEntry_t rt;

				pos = RouteTable.GetHeadPosition();
				for (int i = 0; i < RouteTable.GetCount(); i++)  //遍历路由表(主机序)
				{
					rt = RouteTable.GetNext(pos);
					if ((ntohl(sPacket.DstIP) & rt.Mask) == rt.DstIP)  //找到对应路由
					{
						fl = i;
						if (rt.Mask >= MaxMask)  //最长匹配，1最多
						{
							if (rt.NextHop == 0)  //直接投递
								tmp = ntohl(sPacket.DstIP);
							else
								tmp = rt.NextHop;  //找到下一跳
							MaxMask = rt.Mask;  //更新最长
						}
					}
				}
				if (fl != -1)  //找到
				{
					if (tmp == ntohl(ARPPacket->SendIP))  //缓存队列中有发往该IP地址的报
					{
						memcpy(&IPData, SP.GetNext(ps).PktData, sizeof(Data_t));
						for (int j = 0; j < 6; j++)
						{
							IPData.FrameHeader.DesMAC[j] = ARPPacket->SendHa[j];  //目的MAC设置为收到的ARP报的源地址
							IPData.FrameHeader.SrcMAC[j] = selfmac[j];  //源MAC设置为自身MAC
						}
					}
				}
				//发送IP数据包
				if(pcap_sendpacket(adhandle, (u_char *)&IPData, sizeof(Data_t))!=0)
				{
					AfxMessageBox(_T("发送IP数据报失败！"));
					return ;
				}
				SP.RemoveAt(CurPos);
				//日志输出
				m_logshow.AddString(_T("转发IP数据报：" + long2ip(ntohl(IPData.IPHeader.SrcIP)) + " --> " + long2ip(ntohl(IPData.IPHeader.DstIP))
					+ " , " + char2mac(IPData.FrameHeader.SrcMAC) + " --> " + char2mac(IPData.FrameHeader.DesMAC)));
				m_logshow.SetCurSel(m_logshow.GetCount()-1);
				break;
			}
			fl = 1;  //没有待转发数据包了
		}
	}
}

void Cmy_routerDlg::ICMPDeal(BYTE type, BYTE code, const u_char *pkt_data)  //ICMP数据包
{
	m_logshow.AddString(_T("icmpDeal"));
}

void Cmy_routerDlg::IPDeal(struct pcap_pkthdr *pkt_header, const u_char *pkt_data)  //IP报文处理
{
	//解析IP数据包
	Data_t *IPPacket;
	IPPacket = (Data_t *)pkt_data;
	int length = pkt_header->len;

	WORD RecvChecksum;  //收到的校验和
	WORD CkChecksum;  //校验和检查
	SendBuff_t sb;  //缓存报

	//输出日志
	m_logshow.AddString(_T("收到IP数据报: " + long2ip(ntohl(IPPacket->IPHeader.SrcIP)) + " --> " + long2ip(ntohl(IPPacket->IPHeader.DstIP))));
	m_logshow.SetCurSel(m_logshow.GetCount()-1);

	if(IPPacket->IPHeader.TTL <= 0)
	{
		ICMPDeal(11, 0, pkt_data);  //ICMP错误报告：超时
		return ;
	}

	//int flag = 0;
	////查询IP-MAC映射表
	//if (!IP_MAC.empty())  //不为空
	//{
	//	//IPMAC_t ip_mac;
	//	//POSITION pos;
	//	//pos = IP_MAC.GetHeadPosition();
	//	for (int i = 0; i < IP_MAC.size(); i++)  //查找IP-MAC映射表，主机序
	//	{
	//		//ip_mac = IP_MAC.GetNext(pos);
	//		if (ntohl(IPPacket->IPHeader.SrcIP) == IP_MAC[i].IP)  //IP-MAC映射已存在
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
	//	m_logshow.AddString(_T("未找到IP-MAC映射关系，存入缓存区：" + long2ip(ntohl(IPPacket->IPHeader.SrcIP)) + " --> "
	//		+ char2mac(IPPacket->FrameHeader.SrcMAC)));
	//}

	RecvChecksum = IPPacket->IPHeader.Checksum;

	IPPacket->IPHeader.Checksum = 0;  //置IP头中的校验和为0
	unsigned short check_buff[sizeof(IPHeader_t)];
	memset(check_buff, 0, sizeof(IPHeader_t));
	IPHeader_t *ip_header = &(IPPacket->IPHeader); 
	memcpy(check_buff, ip_header, sizeof(IPHeader_t));

	//重新计算IP头部校验和
	IPPacket->IPHeader.Checksum = ChecksumCompute(check_buff, sizeof(IPHeader_t));
	CkChecksum = IPPacket->IPHeader.Checksum;

	if(RecvChecksum != CkChecksum)  //头部校验错误
	{
		m_logshow.AddString(_T("IP数据包校验和错误，丢弃"));
		m_logshow.SetCurSel(m_logshow.GetCount()-1);
		return ;
	}

	DWORD tmp;
	DWORD MaxMask = 0;  //获取最大子网掩码的地址，最长匹配
	int fl = -1;  //标志
	
	POSITION pos;
	RouteEntry_t rt;

	pos = RouteTable.GetHeadPosition();
	for(int i = 0; i < RouteTable.GetCount(); i++)  //遍历路由表(主机序)
	{
		rt = RouteTable.GetNext(pos);
		if((ntohl(IPPacket->IPHeader.DstIP) & rt.Mask) == rt.DstIP)  //找到对应路由
		{
			fl = i;
			if(rt.Mask >= MaxMask)  //最长匹配，1最多
			{
				if(rt.NextHop == 0)  //直接投递
					tmp = ntohl(IPPacket->IPHeader.DstIP);
				else
					tmp = rt.NextHop;  //找到下一跳
				MaxMask = rt.Mask;  //更新最长
			}
		}
	}
	if(fl == -1)  //没找到
	{
		ICMPDeal(3, 0, pkt_data);  //ICMP错误报告：目的不可达
		return ;
	}
	else
	{
		sb.DstIP = tmp;  //找到了下一地址，缓存待发送数据包至sb
		memcpy(IPPacket->FrameHeader.SrcMAC, selfmac, 6);  //源MAC改为本机MAC
		IPPacket->IPHeader.TTL -= 1;  //TTL减1
		memcpy(sb.PktData, pkt_data, sizeof(Data_t));  //拷贝数据包
		IPPacket->IPHeader.Checksum = 0;  //置IP头中的校验和为0
		unsigned short check_buff[sizeof(IPHeader_t)];
		memset(check_buff, 0, sizeof(IPHeader_t));
		IPHeader_t *ip_header = &(IPPacket->IPHeader);
		memcpy(check_buff, ip_header, sizeof(IPHeader_t));
		//重新计算IP头部校验和
		IPPacket->IPHeader.Checksum = ChecksumCompute(check_buff, sizeof(IPHeader_t));

		//查询IP-MAC映射表
		int fla = 0;  //标志
		if(!IP_MAC.empty())  //不为空
		{

			//IPMAC_t ip_mac;
			//POSITION pos;
			//pos = IP_MAC.GetHeadPosition();
			for(int i = 0; i < IP_MAC.size(); i++)  //查找IP-MAC映射表，主机序
			{
				//ip_mac = IP_MAC.GetAt(pos);
				if(sb.DstIP == IP_MAC[i].IP)  //IP-MAC映射已存在
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
		if (fla == 1)  //找到映射直接发
		{
			if (pcap_sendpacket(adhandle, (u_char *)IPPacket, length) != 0)
			{
				AfxMessageBox(_T("发送IP数据包失败!"));
				return;
			}

			//输出日志
			m_logshow.AddString(_T("转发IP数据报: " + long2ip(ntohl(IPPacket->IPHeader.SrcIP)) + " --> " + long2ip(ntohl(IPPacket->IPHeader.DstIP)) + " , " + char2mac(IPPacket->FrameHeader.SrcMAC) + " --> " + char2mac(IPPacket->FrameHeader.DesMAC)));
			m_logshow.SetCurSel(m_logshow.GetCount() - 1);
			return;
		}
		else//未找到IP-MAC映射关系
		{
			if(SP.GetCount() < 65535)  //容量
			{
				SP.AddTail(sb);  //加入缓存队列
				
				//输出日志

				m_logshow.SetCurSel(m_logshow.GetCount()-1);
				m_logshow.AddString(_T("发送ARP请求。")+ long2ip(sb.DstIP));
				m_logshow.SetCurSel(m_logshow.GetCount()-1);

				//ARP请求报
				DWORD sendip = m_ipaddr2.IPAddr;
				ARPFrame.SendIP = htonl(sendip);
				DWORD recvip = htonl(sb.DstIP);
				ARPFrame.RecvIP = recvip;
				//发送ARP请求
				if(pcap_sendpacket(adhandle,(u_char *)&ARPFrame, sizeof(ARPFrame_t))!=0)
				{
					AfxMessageBox(_T("发送ARP数据包失败!"));
					return ;
				}
			}
			else  //报文过多，丢弃
			{
				m_logshow.AddString(_T("缓存区溢出，丢弃该数据包：" + long2ip(ntohl(IPPacket->IPHeader.SrcIP)) + " --> " + long2ip(ntohl(IPPacket->IPHeader.DstIP))));
				m_logshow.SetCurSel(m_logshow.GetCount()-1);
			}
		}
	}
}

void Cmy_routerDlg::RouterOn()  //路由开关
{
	int res = 0;

	while((res = pcap_next_ex(adhandle, &pkt_header, &pkt_data)) >= 0)
	{
		if(m_flag == false)  //停止抓包，关闭路由
			break ;
		if(res == 0)
		{
			m_logshow.AddString(L"time out.");  //超时
			m_logshow.SetCurSel(m_logshow.GetCount()-1);
			continue;
		}
		FrameHeader_t *fh;
		fh = (FrameHeader_t *)pkt_data;
		if(ntohs(fh->FrameType)==0x0806)  //ARP
		{
			ARPDeal(pkt_header, pkt_data);  //处理ARP报文
		}
		else if(ntohs(fh->FrameType)==0x0800)  //IP
		{
			IPDeal(pkt_header, pkt_data);  //处理IP报文
		}
	}
	//pcap_close(adhandle);
	//释放设备列表
	pcap_freealldevs(alldevs);
	return ;
}



void Cmy_routerDlg::OnBnClickedAddrtr()  //添加路由表项
{
	// TODO:  在此添加控件通知处理程序代码
	DWORD ipaddr;
	RouteEntry_t rt;
	POSITION pos, CurrentPos;
	//下一跳步
	m_nexthop.GetAddress(ipaddr);
	rt.NextHop = ipaddr;
	//目的IP
	m_dstaddr.GetAddress(ipaddr);
	rt.DstIP = ipaddr;
	//子网掩码
	m_mask.GetAddress(ipaddr);
	rt.Mask = ipaddr;
	
	RouteEntry_t rtmp;
	pos = RouteTable.GetHeadPosition();
	for(int i = 0; i < RouteTable.GetCount(); i++)  //所添加路由表项已经存在
	{
		CurrentPos = pos;
		rtmp = RouteTable.GetNext(pos);
		if ((rt.Mask == rtmp.Mask) && (rt.DstIP == rtmp.DstIP) && (rt.NextHop == rtmp.NextHop))
		{
			MessageBox(_T("已经存在！"));
			return ;
		}
	}
	//不存在
	if(((m_ipaddr1.IPNetmask) & rt.NextHop) == ((m_ipaddr1.IPNetmask) & m_ipaddr1.IPAddr)
		||((m_ipaddr2.IPNetmask) & rt.NextHop) == ((m_ipaddr2.IPNetmask) & m_ipaddr2.IPAddr))  //判断能否到达
	{
		//添加到路由表
		RouteTable.AddTail(rt);
		//显示
		m_rtrtable.AddString(long2ip(rt.Mask) + " -- " + 
			long2ip(rt.DstIP) + " -- " + long2ip(rt.NextHop));
	}
	else
	{
		MessageBox(_T("输入错误！"));
	}
	// TODO: 在此添加控件通知处理程序代码
}


void Cmy_routerDlg::OnBnClickedDelrtr()  //删除路由表项
{
	// TODO:  在此添加控件通知处理程序代码
	DWORD ipaddr;
	RouteEntry_t rt;
	POSITION pos, CurrentPos, p;
	//下一跳步
	m_nexthop.GetAddress(ipaddr);
	rt.NextHop = ipaddr;
	//目的IP
	m_dstaddr.GetAddress(ipaddr);
	rt.DstIP = ipaddr;
	//子网掩码
	m_mask.GetAddress(ipaddr);
	rt.Mask = ipaddr;

	if(rt.NextHop == 0)  //直接连接
	{
		MessageBox(_T("直接连接路由，删除失败！"));
		return;
	}

	//遍历路由表，删除路由表项
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
			fl = 1;  //标志找到
			break ;
		}
	}
	if(fl == 0)
	{
		MessageBox(_T("查无此项，删除失败！"));
		return ;
	}
	m_rtrtable.ResetContent();  //显示列表重置
	p = RouteTable.GetHeadPosition();
	for(int i = 0; i < RouteTable.GetCount(); i++)
	{
		rtmp = RouteTable.GetNext(p);
		if(rtmp.NextHop == 0)  //直接投递
			m_rtrtable.AddString(long2ip(rtmp.Mask) + " -- " + long2ip(rtmp.DstIP) + " -- " + long2ip(rtmp.NextHop) + " (直接投递)");
		else
			m_rtrtable.AddString(long2ip(rtmp.Mask) + " -- " + long2ip(rtmp.DstIP) + " -- " + long2ip(rtmp.NextHop));
	}
}


void Cmy_routerDlg::OnBnClickedBack()
{
	// TODO: 在此添加控件通知处理程序代码
	m_logshow.ResetContent();  //清空日志

}


UINT Capturer(LPVOID hWnd)
{
	Cmy_routerDlg *pDlg = (Cmy_routerDlg *)hWnd;
	pDlg->RouterOn();  //路由开关

    return 1;
}


void Cmy_routerDlg::OnBnClickedStart()
{
	if(m_flag == true)  //停止捕获
	{
		m_flag = false;
		m_logshow.AddString(_T("路由关闭。"));
		m_logshow.SetCurSel(m_logshow.GetCount()-1);
	}
	else  //开始捕获
	{
		m_flag = true;
		m_logshow.AddString(_T("路由打开。"));
		m_logshow.SetCurSel(m_logshow.GetCount()-1);
		//启动线程开始抓包
		m_thread = AfxBeginThread(Capturer,this,THREAD_PRIORITY_NORMAL);
	}
	// TODO: 在此添加控件通知处理程序代码
}
