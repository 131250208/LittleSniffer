package com.mysniffer.service.impl;

import java.util.List;

import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.EthernetPacket.EthernetHeader;
import org.pcap4j.packet.Packet;
import org.springframework.stereotype.Service;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.mysniffer.service.PackageService;

@Service
public class PackageServiceImpl implements PackageService {

	private CaptureThread cThread = null;

	private String bytesToHex(byte[] bytes) {
		StringBuilder buf = new StringBuilder(bytes.length * 2);
		for (byte b : bytes) {
			buf.append(String.format("%02x ", new Integer(b & 0xff)));
		}

		return buf.toString();
	}

	public String getPacketInfoJSON(Packet packet) {
		JSONObject job = new JSONObject();
		if (packet.getOuterOf(ArpPacket.class) != null) {
			EthernetHeader ethernetHeader = (EthernetHeader) packet.getHeader();
			ArpPacket arpPacket = (ArpPacket) packet.get(ArpPacket.class);

			job.put("type", "arp");

			// JSONObject job_eth = new JSONObject();
			// job_eth.put("dest_addr", ethernetHeader.getDstAddr());
			// job_eth.put("src_addr", ethernetHeader.getSrcAddr());
			// job_eth.put("type", ethernetHeader.getType());

			String dest_hard = arpPacket.getHeader().getDstHardwareAddr().toString();
			String dest_pro = arpPacket.getHeader().getDstProtocolAddr().toString();
			String src_hard = arpPacket.getHeader().getSrcHardwareAddr().toString();
			String src_pro = arpPacket.getHeader().getSrcProtocolAddr().toString();
			int length = packet.length();

			job.put("eth_header", ethernetHeader.toString());
			job.put("arp_header", arpPacket.toString());
			job.put("pkg_hex", bytesToHex(packet.getRawData()));
			job.put("dest_hard", dest_hard);
			job.put("dest_pro", dest_pro);
			job.put("src_hard", src_hard);
			job.put("src_pro", src_pro);
			job.put("length", length);

			String info = String.format("Who has %s? Tell %s", dest_pro, src_pro);
			if (dest_pro.equals(src_pro)) {
				info = String.format("Gratuitous ARP for %s (Request) (duplicate use of 111.195.219.30 detected!)",
						dest_pro);
			}

			job.put("info", info);
		}
		return job.toJSONString();
	}

	public String getDevicesList() {
		List<PcapNetworkInterface> devices = null;
		try {
			devices = Pcaps.findAllDevs();
		} catch (PcapNativeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		JSONObject jsonObject = new JSONObject();
		jsonObject.put("tag", "devices_list");

		JSONArray jsonArray = new JSONArray();
		for (PcapNetworkInterface n : devices) {
			System.out.println(n.getName() + " | " + n.getDescription());
			JSONObject job = new JSONObject();
			job.put("name", n.getName());
			job.put("des", n.getDescription());

			jsonArray.add(job);
		}
		jsonObject.put("devices", jsonArray);

		System.out.println("-------------------------------------------");
		return jsonObject.toJSONString();
	}
	//
	// public void capture_packages() {
	// NetworkInterface[] devices = null;
	// JpcapCaptor jpcap = null;
	// try {
	// devices = JpcapCaptor.getDeviceList();
	//
	// int caplen = 65535;
	// boolean promiscCheck = true;
	//
	// jpcap = JpcapCaptor.openDevice(devices[2], caplen, promiscCheck, 50);
	// jpcap.setFilter("ip or arp", true);
	// } catch (Exception e) {
	// e.printStackTrace();
	// }
	//
	// /*----------�ڶ���ץ��-----------------*/
	// int i = 0;
	// while (true) {
	// Packet packet = jpcap.getPacket();
	// if (packet instanceof IPPacket && ((IPPacket) packet).version == 4) {
	// i++;
	// IPPacket ip = (IPPacket) packet;// ǿת
	//
	// System.out.println(String.format("packet %s", i));
	// System.out.println("�汾��IPv4");
	// System.out.println("����Ȩ��" + ip.priority);
	// System.out.println("���ַ��������������� " + ip.t_flag);
	// System.out.println("���ַ�����ߵĿɿ��ԣ�" + ip.r_flag);
	// System.out.println("���ȣ�" + ip.length);
	// System.out.println("��ʶ��" + ip.ident);
	// System.out.println("DF:Don't Fragment: " + ip.dont_frag);
	// System.out.println("NF:More Fragment: " + ip.more_frag);
	// System.out.println("Ƭƫ�ƣ�" + ip.offset);
	// System.out.println("����ʱ�䣺" + ip.hop_limit);
	//
	// String protocol = "";
	// switch (ip.protocol) {
	// case IPPacket.IPPROTO_ICMP:
	// protocol = "ICMP";
	// break;
	// case IPPacket.IPPROTO_IGMP:
	// protocol = "IGMP";
	// break;
	// case IPPacket.IPPROTO_TCP:
	// protocol = "TCP";
	// break;
	// case IPPacket.IPPROTO_UDP:
	// protocol = "UDP";
	// break;
	// default:
	// break;
	// }
	// System.out.println("Э�飺" + protocol);
	// System.out.println("ԴIP " + ip.src_ip.getHostAddress());
	// System.out.println("Ŀ��IP " + ip.dst_ip.getHostAddress());
	// System.out.println("Դ�������� " + ip.src_ip);
	// System.out.println("Ŀ���������� " + ip.dst_ip);
	// System.out.println("���ݣ�" + new String(ip.data));
	//
	// System.out.println("----------------------------------------------");
	// } else if (packet instanceof ARPPacket) {
	// i++;
	// ARPPacket arpPacket = (ARPPacket) packet;
	// System.out.println(String.format("��%d��packet", i));
	// System.out.println(String.format("protocol: %s", "ARP"));
	//
	// switch (arpPacket.operation) {
	// case ARPPacket.ARP_REPLY:
	// System.out.println(String.format("operation: %s", "ARP_REPLY"));
	// break;
	// case ARPPacket.ARP_REQUEST:
	// System.out.println(String.format("operation: %s", "ARP_REQUEST"));
	// break;
	// case ARPPacket.RARP_REPLY:
	// System.out.println(String.format("operation: %s", "RARP_REPLY"));
	// break;
	// case ARPPacket.RARP_REQUEST:
	// System.out.println(String.format("operation: %s", "RARP_REQUEST"));
	// break;
	// case ARPPacket.INV_REPLY:
	// System.out.println(String.format("operation: %s", "INV_REPLY"));
	// break;
	// case ARPPacket.INV_REQUEST:
	// System.out.println(String.format("operation: %s", "INV_REQUEST"));
	// break;
	// }
	//
	// switch (arpPacket.hardtype) {
	// case ARPPacket.HARDTYPE_ETHER:
	// System.out.println(String.format("hardtype: %s", "ETHER"));
	// break;
	// case ARPPacket.HARDTYPE_FRAMERELAY:
	// System.out.println(String.format("hardtype: %s", "FRAMERELAY"));
	// break;
	// case ARPPacket.HARDTYPE_IEEE802:
	// System.out.println(String.format("hardtype: %s", "IEEE802"));
	// break;
	// }
	//
	// System.out.println(String.format("header: %s",
	// bytesToHex(arpPacket.header)));
	// System.out.println(String.format("data: %s",
	// bytesToHex(arpPacket.data)));
	//
	// System.out.println(String.format("sender_hw_address: %s",
	// arpPacket.getSenderHardwareAddress()));
	// System.out.println(String.format("sender_pr_address: %s",
	// arpPacket.getSenderProtocolAddress()));
	// System.out.println(String.format("target_hw_address: %s",
	// arpPacket.getTargetHardwareAddress()));
	// System.out.println(String.format("target_pr_address: %s",
	// arpPacket.getTargetProtocolAddress()));
	//
	// // System.out.println(String.format("color: %s", arpPacket.));
	// System.out.println("----------------------------------------------");
	//
	// }
	// }
	// }

	public void capture_packages_Pcap4j(int dev_num, String filter, PacketListener listener) {
		if (cThread != null && cThread.isHandleOpen()) {
			cThread.closeHandle();
		}
		cThread = new CaptureThread(dev_num, filter, listener);
		cThread.start();
	}

	class CaptureThread extends Thread {
		private int dev_num;
		private String filter;
		private PacketListener listener;

		private PcapHandle handle = null;

		public CaptureThread(int dev_num, String filter, PacketListener listener) {
			// TODO Auto-generated constructor stub
			this.dev_num = dev_num;
			this.filter = filter;
			this.listener = listener;
		}

		public void closeHandle() {
			try {
				if (handle.isOpen()) {
					handle.breakLoop();
				}
			} catch (NotOpenException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}

		public boolean isHandleOpen() {
			return (handle != null) && (handle.isOpen());
		}

		@Override
		public void run() {
			// TODO Auto-generated method stub
			super.run();
			// 获取所有网卡设备
			List<PcapNetworkInterface> alldev = null;
			try {
				alldev = Pcaps.findAllDevs();
			} catch (PcapNativeException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

			// 根据设备名称初始化抓包接口
			PcapNetworkInterface nif = null;
			try {
				String dev_name = alldev.get(dev_num).getName();
				nif = Pcaps.getDevByName(dev_name);
				this.setName(dev_name);
			} catch (PcapNativeException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

			// 抓取包长度
			int snaplen = 64 * 1024;
			// 超时50ms
			int timeout = 50;
			// 初始化抓包器
			PcapHandle.Builder phb = new PcapHandle.Builder(nif.getName()).snaplen(snaplen)
					.promiscuousMode(PromiscuousMode.PROMISCUOUS).timeoutMillis(timeout).bufferSize(1 * 1024 * 1024);

			try {
				handle = phb.build();
			} catch (PcapNativeException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			// handle = nif.openLive(snaplen, PromiscuousMode.NONPROMISCUOUS,
			// timeout);

			try {
				// 设置过滤器
				handle.setFilter(filter, BpfCompileMode.OPTIMIZE);

				// 监听
				System.out.println("开始抓包");
				handle.loop(25, listener);
				System.out.println(String.format("%s 抓包结束", this.getName()));
			} catch (PcapNativeException | NotOpenException | InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

		}
	}
}
