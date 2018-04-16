package com.mysniffer.service.impl;

import java.io.IOException;

import org.springframework.stereotype.Service;

import com.mysniffer.service.PackageService;

import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;
import jpcap.packet.ARPPacket;
import jpcap.packet.IPPacket;
import jpcap.packet.Packet;

@Service
public class PackageServiceImpl implements PackageService {

	public String bytesToHex(byte[] bytes) {
		StringBuilder buf = new StringBuilder(bytes.length * 2);
		for (byte b : bytes) {
			buf.append(String.format("%02x ", new Integer(b & 0xff)));
		}

		return buf.toString();
	}

	public void capture_packages() {
		/*--------------    ��һ���������豸       --------------*/
		NetworkInterface[] devices = JpcapCaptor.getDeviceList();

		for (NetworkInterface n : devices) {
			System.out.println(n.name + "     |     " + n.description);
		}
		System.out.println("-------------------------------------------");

		JpcapCaptor jpcap = null;
		int caplen = 65535;
		boolean promiscCheck = true;

		try {
			jpcap = JpcapCaptor.openDevice(devices[2], caplen, promiscCheck, 50);
			jpcap.setFilter("ip or arp", true);
		} catch (IOException e) {
			e.printStackTrace();
		}

		/*----------�ڶ���ץ��-----------------*/
		int i = 0;
		while (true) {
			Packet packet = jpcap.getPacket();
			if (packet instanceof IPPacket && ((IPPacket) packet).version == 4) {
				i++;
				IPPacket ip = (IPPacket) packet;// ǿת

				System.out.println(String.format("packet %s", i));
				System.out.println("�汾��IPv4");
				System.out.println("����Ȩ��" + ip.priority);
				System.out.println("���ַ��������������� " + ip.t_flag);
				System.out.println("���ַ�����ߵĿɿ��ԣ�" + ip.r_flag);
				System.out.println("���ȣ�" + ip.length);
				System.out.println("��ʶ��" + ip.ident);
				System.out.println("DF:Don't Fragment: " + ip.dont_frag);
				System.out.println("NF:More Fragment: " + ip.more_frag);
				System.out.println("Ƭƫ�ƣ�" + ip.offset);
				System.out.println("����ʱ�䣺" + ip.hop_limit);

				String protocol = "";
				switch (ip.protocol) {
				case IPPacket.IPPROTO_ICMP:
					protocol = "ICMP";
					break;
				case IPPacket.IPPROTO_IGMP:
					protocol = "IGMP";
					break;
				case IPPacket.IPPROTO_TCP:
					protocol = "TCP";
					break;
				case IPPacket.IPPROTO_UDP:
					protocol = "UDP";
					break;
				default:
					break;
				}
				System.out.println("Э�飺" + protocol);
				System.out.println("ԴIP " + ip.src_ip.getHostAddress());
				System.out.println("Ŀ��IP " + ip.dst_ip.getHostAddress());
				System.out.println("Դ�������� " + ip.src_ip);
				System.out.println("Ŀ���������� " + ip.dst_ip);
				System.out.println("���ݣ�" + new String(ip.data));

				System.out.println("----------------------------------------------");
			} else if (packet instanceof ARPPacket) {
				i++;
				ARPPacket arpPacket = (ARPPacket) packet;
				System.out.println(String.format("��%d��packet", i));
				System.out.println(String.format("protocol: %s", "ARP"));

				switch (arpPacket.operation) {
				case ARPPacket.ARP_REPLY:
					System.out.println(String.format("operation: %s", "ARP_REPLY"));
					break;
				case ARPPacket.ARP_REQUEST:
					System.out.println(String.format("operation: %s", "ARP_REQUEST"));
					break;
				case ARPPacket.RARP_REPLY:
					System.out.println(String.format("operation: %s", "RARP_REPLY"));
					break;
				case ARPPacket.RARP_REQUEST:
					System.out.println(String.format("operation: %s", "RARP_REQUEST"));
					break;
				case ARPPacket.INV_REPLY:
					System.out.println(String.format("operation: %s", "INV_REPLY"));
					break;
				case ARPPacket.INV_REQUEST:
					System.out.println(String.format("operation: %s", "INV_REQUEST"));
					break;
				}

				switch (arpPacket.hardtype) {
				case ARPPacket.HARDTYPE_ETHER:
					System.out.println(String.format("hardtype: %s", "ETHER"));
					break;
				case ARPPacket.HARDTYPE_FRAMERELAY:
					System.out.println(String.format("hardtype: %s", "FRAMERELAY"));
					break;
				case ARPPacket.HARDTYPE_IEEE802:
					System.out.println(String.format("hardtype: %s", "IEEE802"));
					break;
				}

				System.out.println(String.format("header: %s", bytesToHex(arpPacket.header)));
				System.out.println(String.format("data: %s", bytesToHex(arpPacket.data)));

				System.out.println(String.format("sender_hw_address: %s", arpPacket.getSenderHardwareAddress()));
				System.out.println(String.format("sender_pr_address: %s", arpPacket.getSenderProtocolAddress()));
				System.out.println(String.format("target_hw_address: %s", arpPacket.getTargetHardwareAddress()));
				System.out.println(String.format("target_pr_address: %s", arpPacket.getTargetProtocolAddress()));

				// System.out.println(String.format("color: %s", arpPacket.));
				System.out.println("----------------------------------------------");

			}
		}
	}
}
