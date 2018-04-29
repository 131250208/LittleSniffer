package com.mysniffer.service.impl;

import java.io.IOException;
import java.util.Date;
import java.util.List;
import java.util.Queue;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.ArpPacket.ArpHeader;
import org.pcap4j.packet.EthernetPacket.EthernetHeader;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IcmpV4CommonPacket.IcmpV4CommonHeader;
import org.pcap4j.packet.IcmpV4DestinationUnreachablePacket;
import org.pcap4j.packet.IcmpV4DestinationUnreachablePacket.IcmpV4DestinationUnreachableHeader;
import org.pcap4j.packet.IcmpV4EchoPacket;
import org.pcap4j.packet.IcmpV4EchoPacket.IcmpV4EchoHeader;
import org.pcap4j.packet.IcmpV4EchoReplyPacket;
import org.pcap4j.packet.IcmpV4EchoReplyPacket.IcmpV4EchoReplyHeader;
import org.pcap4j.packet.IcmpV4ParameterProblemPacket;
import org.pcap4j.packet.IcmpV4ParameterProblemPacket.IcmpV4ParameterProblemHeader;
import org.pcap4j.packet.IcmpV4RedirectPacket;
import org.pcap4j.packet.IcmpV4RedirectPacket.IcmpV4RedirectHeader;
import org.pcap4j.packet.IcmpV4SourceQuenchPacket;
import org.pcap4j.packet.IcmpV4SourceQuenchPacket.IcmpV4SourceQuenchHeader;
import org.pcap4j.packet.IcmpV4TimeExceededPacket;
import org.pcap4j.packet.IcmpV4TimeExceededPacket.IcmpV4TimeExceededHeader;
import org.pcap4j.packet.IcmpV4TimestampPacket;
import org.pcap4j.packet.IcmpV4TimestampPacket.IcmpV4TimestampHeader;
import org.pcap4j.packet.IcmpV4TimestampReplyPacket;
import org.pcap4j.packet.IcmpV4TimestampReplyPacket.IcmpV4TimestampReplyHeader;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV4Packet.IpV4Header;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.TcpPacket.TcpHeader;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.UdpPacket.UdpHeader;
import org.pcap4j.packet.namednumber.IcmpV4Type;
import org.pcap4j.packet.namednumber.IpNumber;
import org.springframework.stereotype.Service;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.mysniffer.service.PackageService;

@Service
public class PackageServiceImpl implements PackageService {

	private CaptureThread captureThread = null;

	private SendPacketThread sendPacketsThread = null;

	private String bytesToHexAndChar(byte[] bytes) {
		StringBuilder buf_hex = new StringBuilder(bytes.length * 4);
		StringBuilder buf = new StringBuilder(bytes.length * 6);
		char[] char_list = new char[18];
		int j = 0;

		for (int i = 0; i < bytes.length; ++i) {
			// buf
			buf_hex.append(String.format("%02x ", new Integer(bytes[i] & 0xff)));
			if ((i + 1) % 8 == 0)
				buf_hex.append(" ");

			// char
			int b = new Integer(bytes[i] & 0xff);
			char c = '.';
			if (b >= 32 && b <= 126) {
				c = (char) b;
			}

			char_list[j++] = c;
			if ((i + 1) % 8 == 0) {
				char_list[j++] = ' ';

			}
			if ((i + 1) % 16 == 0) {
				buf.append(String.format("%s             %s \n", buf_hex.toString(), String.valueOf(char_list)));
				j = 0;
				char_list = new char[18];
				buf_hex.delete(0, buf_hex.length());
			}
		}
		buf.append(String.format("%s             %s \n", buf_hex.toString(), String.valueOf(char_list)));

		return buf.toString();
	}

	private String bytesToString(byte[] bytes) {
		char[] char_list = new char[bytes.length];

		for (int i = 0; i < bytes.length; ++i) {
			int b = new Integer(bytes[i] & 0xff);
			char c = '.';
			if (b >= 32 && b <= 126) {
				c = (char) b;
			}

			char_list[i] = c;
		}
		return String.valueOf(char_list);
	}

	private JSONObject dealIcmpv3(JSONObject job, Packet packet) {
		IpV4Packet ipV4Packet = (IpV4Packet) packet.get(IpV4Packet.class);
		IpV4Header ipV4Header = ipV4Packet.getHeader();

		IcmpV4CommonPacket icmpV4CommonPacket = (IcmpV4CommonPacket) packet.get(IcmpV4CommonPacket.class);
		IcmpV4CommonHeader icmpV4CommonHeader = (IcmpV4CommonHeader) icmpV4CommonPacket.getHeader();
		IcmpV4Type icmpV4Type = icmpV4CommonHeader.getType();
		job.put("type", "ICMPv4");

		job.put("src_port", "-");
		job.put("dest_port", "-");

		if (icmpV4Type.compareTo(IcmpV4Type.ECHO) == 0) {
			IcmpV4EchoPacket icmpV4EchoPacket = (IcmpV4EchoPacket) packet.get(IcmpV4EchoPacket.class);
			IcmpV4EchoHeader icmpV4EchoHeader = icmpV4EchoPacket.getHeader();
			short id = icmpV4EchoHeader.getIdentifier();
			short seq = icmpV4EchoHeader.getSequenceNumber();
			job.put("info", String.format("%s id=%d, seq=%d, ttl=%d", icmpV4Type.toString(), id, seq,
					ipV4Header.getTtlAsInt()));

			job.put("special_header",
					String.format("%s\n%s", icmpV4CommonPacket.getHeader(), icmpV4EchoHeader).replace("\r\n", "<br/>"));
		} else if (icmpV4Type.compareTo(IcmpV4Type.PARAMETER_PROBLEM) == 0) {
			IcmpV4ParameterProblemPacket icmpV4ParameterProblemPacket = (IcmpV4ParameterProblemPacket) packet
					.get(IcmpV4ParameterProblemPacket.class);
			IcmpV4ParameterProblemHeader icmpV4ParameterProblemHeader = icmpV4ParameterProblemPacket.getHeader();
			int pointer = icmpV4ParameterProblemHeader.getPointerAsInt();

			job.put("info", String.format("%s  %s", icmpV4Type.toString(), icmpV4CommonHeader.getCode().toString()));
			job.put("special_header",
					String.format("%s\n%s", icmpV4CommonHeader.toString(), icmpV4ParameterProblemHeader.toString())
							.replace("\r\n", "<br/>"));
		} else if (icmpV4Type.compareTo(IcmpV4Type.DESTINATION_UNREACHABLE) == 0) {
			IcmpV4DestinationUnreachablePacket icmpV4DestinationUnreachablePacket = (IcmpV4DestinationUnreachablePacket) packet
					.get(IcmpV4DestinationUnreachablePacket.class);
			IcmpV4DestinationUnreachableHeader icmpV4DestinationUnreachableHeader = icmpV4DestinationUnreachablePacket
					.getHeader();

			job.put("info", String.format("%s  %s", icmpV4Type.toString(), icmpV4CommonHeader.getCode().toString()));
			job.put("special_header", String
					.format("%s\n%s", icmpV4CommonHeader.toString(), icmpV4DestinationUnreachableHeader.toString())
					.replace("\r\n", "<br/>"));
		} else if (icmpV4Type.compareTo(IcmpV4Type.SOURCE_QUENCH) == 0) {
			IcmpV4SourceQuenchPacket icmpV4SourceQuenchPacket = (IcmpV4SourceQuenchPacket) packet
					.get(IcmpV4SourceQuenchPacket.class);
			IcmpV4SourceQuenchHeader icmpV4SourceQuenchHeader = icmpV4SourceQuenchPacket.getHeader();

			job.put("info", String.format("%s  %s", icmpV4Type.toString(), icmpV4CommonHeader.getCode().toString()));
			job.put("special_header",
					String.format("%s\n%s", icmpV4CommonHeader.toString(), icmpV4SourceQuenchHeader.toString())
							.replace("\r\n", "<br/>"));
		} else if (icmpV4Type.compareTo(IcmpV4Type.TIME_EXCEEDED) == 0) {
			IcmpV4TimeExceededPacket icmpV4TimeExceededPacket = (IcmpV4TimeExceededPacket) packet
					.get(IcmpV4TimeExceededPacket.class);
			IcmpV4TimeExceededHeader icmpV4TimeExceededHeader = icmpV4TimeExceededPacket.getHeader();

			job.put("info", String.format("%s  %s", icmpV4Type.toString(), icmpV4CommonHeader.getCode().toString()));
			job.put("special_header",
					String.format("%s\n%s", icmpV4CommonHeader.toString(), icmpV4TimeExceededHeader.toString())
							.replace("\r\n", "<br/>"));
		} else if (icmpV4Type.compareTo(IcmpV4Type.REDIRECT) == 0) {
			IcmpV4RedirectPacket icmpV4RedirectPacket = (IcmpV4RedirectPacket) packet.get(IcmpV4RedirectPacket.class);
			IcmpV4RedirectHeader icmpV4RedirectHeader = icmpV4RedirectPacket.getHeader();

			job.put("info", String.format("%s  %s", icmpV4Type.toString(), icmpV4CommonHeader.getCode().toString()));
			job.put("special_header",
					String.format("%s\n%s", icmpV4CommonHeader.toString(), icmpV4RedirectHeader.toString())
							.replace("\r\n", "<br/>"));
		} else if (icmpV4Type.compareTo(IcmpV4Type.TIMESTAMP) == 0) {
			IcmpV4TimestampPacket icmpV4TimestampPacket = (IcmpV4TimestampPacket) packet
					.get(IcmpV4TimestampPacket.class);
			IcmpV4TimestampHeader icmpV4TimestampHeader = icmpV4TimestampPacket.getHeader();

			job.put("info", String.format("%s  %s", icmpV4Type.toString(), icmpV4CommonHeader.getCode().toString()));
			job.put("special_header",
					String.format("%s\n%s", icmpV4CommonHeader.toString(), icmpV4TimestampHeader.toString())
							.replace("\r\n", "<br/>"));
		} else if (icmpV4Type.compareTo(IcmpV4Type.TIMESTAMP_REPLY) == 0) {
			IcmpV4TimestampReplyPacket icmpV4TimestampReplyPacket = (IcmpV4TimestampReplyPacket) packet
					.get(IcmpV4TimestampReplyPacket.class);
			IcmpV4TimestampReplyHeader icmpV4TimestampReplyHeader = icmpV4TimestampReplyPacket.getHeader();

			job.put("info", String.format("%s  %s", icmpV4Type.toString(), icmpV4CommonHeader.getCode().toString()));
			job.put("special_header",
					String.format("%s\n%s", icmpV4CommonHeader.toString(), icmpV4TimestampReplyHeader.toString())
							.replace("\r\n", "<br/>"));
		} else if (icmpV4Type.compareTo(IcmpV4Type.ECHO_REPLY) == 0) {
			IcmpV4EchoReplyPacket icmpV4EchoReplyPacket = (IcmpV4EchoReplyPacket) packet
					.get(IcmpV4EchoReplyPacket.class);
			IcmpV4EchoReplyHeader icmpV4EchoReplyHeader = icmpV4EchoReplyPacket.getHeader();

			job.put("info", String.format("%s  %s", icmpV4Type.toString(), icmpV4CommonHeader.getCode().toString()));
			job.put("special_header",
					String.format("%s\n%s", icmpV4CommonHeader.toString(), icmpV4EchoReplyHeader.toString())
							.replace("\r\n", "<br/>"));
		}
		return job;
	}

	private JSONObject dealIpv4(JSONObject job, Packet packet) {
		IpV4Packet ipV4Packet = (IpV4Packet) packet.get(IpV4Packet.class);
		IpV4Header ipV4Header = ipV4Packet.getHeader();

		String src_pro = ipV4Header.getSrcAddr().getHostAddress();
		String dest_pro = ipV4Header.getDstAddr().getHostAddress();
		job.put("dest_addr", dest_pro);
		job.put("src_addr", src_pro);
		job.put("dest_ip", dest_pro);
		job.put("src_ip", src_pro);
		job.put("ipv4_header", ipV4Header.toString().replace("\r\n", "<br/>"));

		if (packet.get(UdpPacket.class) != null) {// udp
			job.put("type", "UDP");

			UdpPacket udpPacket = (UdpPacket) packet.get(UdpPacket.class);
			UdpHeader udpHeader = udpPacket.getHeader();

			String src_port = udpHeader.getSrcPort().toString();
			String dest_port = udpHeader.getDstPort().toString();
			job.put("src_port", udpHeader.getSrcPort().valueAsInt());
			job.put("dest_port", udpHeader.getDstPort().valueAsInt());

			int len_data = udpHeader.getLengthAsInt() - 8;
			String info = String.format("%s -> %s Len=%d", src_port, dest_port, len_data);
			job.put("info", info);
			job.put("special_header", udpHeader.toString().replace("\r\n", "<br/>"));
			if (udpPacket.getPayload() != null) {
				job.put("data", udpPacket.getPayload().toString());
			} else {
				job.put("data", "no payload");
			}

		} else if (packet.get(TcpPacket.class) != null) {// tcp
			job.put("type", "TCP");
			TcpPacket tcpPacket = (TcpPacket) packet.get(TcpPacket.class);
			TcpHeader tcpHeader = tcpPacket.getHeader();
			long ack_num_l = tcpHeader.getAcknowledgmentNumberAsLong();
			long seq_num_l = tcpHeader.getSequenceNumberAsLong();
			String src_port = tcpHeader.getSrcPort().toString();
			String dest_port = tcpHeader.getDstPort().toString();
			job.put("src_port", tcpHeader.getSrcPort().valueAsInt());
			job.put("dest_port", tcpHeader.getDstPort().valueAsInt());

			String tag = "[";

			if (tcpHeader.getAck())
				tag += "Ack, ";
			if (tcpHeader.getFin())
				tag += "Fin, ";
			if (tcpHeader.getPsh())
				tag += "Psh, ";
			if (tcpHeader.getRst())
				tag += "Rst, ";
			if (tcpHeader.getSyn())
				tag += "Syn, ";
			if (tcpHeader.getUrg())
				tag += "Urg, ";

			tag = tag.substring(0, tag.length() - 2) + "]";

			int win = tcpHeader.getWindowAsInt();
			int len = 0;
			if (tcpPacket.getPayload() != null) {
				len = tcpPacket.getPayload().length();
			}

			job.put("info", String.format("%s -> %s %s Seq=%d Ack=%d Win=%d Len=%d", src_port, dest_port, tag,
					seq_num_l, ack_num_l, win, len));
			job.put("special_header", tcpHeader.toString().replace("\r\n", "<br/>"));

			if (tcpPacket.getPayload() != null) {
				job.put("data", tcpPacket.getPayload().toString());
			} else {
				job.put("data", "no payload");
			}

			// identify http
			job.put("app_header", "-");
			String pkg_hex_char = bytesToString(packet.getRawData());
			if (pkg_hex_char.indexOf("HTTP/1.1") != -1) {
				Pattern http_post = Pattern.compile("POST .+ HTTP/1\\.1\\.\\..+");
				Pattern http_get = Pattern.compile("GET .+ HTTP/1\\.1\\.\\..+");
				Pattern http_re = Pattern.compile("HTTP/1\\.1 \\d{3} .+\\.\\..+");

				String http = "";
				Matcher m = null;
				if ((m = http_post.matcher(pkg_hex_char)).find()) {
					http = m.group(0);
				} else if ((m = http_get.matcher(pkg_hex_char)).find()) {
					http = m.group(0);
				} else if ((m = http_re.matcher(pkg_hex_char)).find()) {
					http = m.group(0);
				}

				job.put("app_header", http.replace("..", "\n"));
				job.put("type", "HTTP");
			}

		} else if (packet.get(IcmpV4CommonPacket.class) != null) {// icmp
			job = dealIcmpv3(job, packet);
		} else if (ipV4Packet.getHeader().getProtocol().compareTo(IpNumber.IGMP) == 0) {// igmp
			job.put("type", "IGMPv3");
			// packet.get()
		}
		return job;
	}

	private JSONObject getPacketInfoJSON(Packet packet, double time) {
		JSONObject job = new JSONObject();
		job.put("tag", "packet");
		job.put("time", String.valueOf(time));

		EthernetHeader ethernetHeader = (EthernetHeader) packet.getHeader();
		job.put("eth_header", ethernetHeader.toString().replace("\r\n", "<br/>"));

		String pkg_hex_char = bytesToHexAndChar(packet.getRawData());

		job.put("pkg_hex_char", pkg_hex_char);

		int length = packet.length();
		job.put("length", length);

		if (packet.getOuterOf(ArpPacket.class) != null) {// arp
			job.put("type", "ARP");
			job.put("src_port", "-");
			job.put("dest_port", "-");

			ArpPacket arpPacket = (ArpPacket) packet.get(ArpPacket.class);
			ArpHeader arpHeader = arpPacket.getHeader();
			String dest_hard = arpHeader.getDstHardwareAddr().toString();
			String dest_pro = arpHeader.getDstProtocolAddr().toString();
			String src_hard = arpHeader.getSrcHardwareAddr().toString();
			String src_pro = arpHeader.getSrcProtocolAddr().toString();

			String arp_header_str = arpPacket.getHeader().toString().replace("\r\n", "<br/>");
			job.put("arp_header", arp_header_str);
			job.put("dest_addr", dest_hard);
			job.put("src_addr", src_hard);

			job.put("src_ip", arpHeader.getSrcProtocolAddr().getHostAddress());
			job.put("dest_ip", "0.0.0.0");

			String info = String.format("Who has %s? Tell %s", dest_pro, src_pro);
			if (dest_pro.equals(src_pro)) {
				info = String.format("Gratuitous ARP for %s (Request) (duplicate use of 111.195.219.30 detected!)",
						dest_pro);
			}
			job.put("info", info);
		} else if (packet.get(IpV4Packet.class) != null) {// ipv4类型
			job = dealIpv4(job, packet);
		} else {
			return null;
		}
		return job;
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

	private void sendMessage(WebSocketSession session, String msg) {
		try {
			session.sendMessage(new TextMessage(msg));
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
			System.out.println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!发送消息出错...\n" + e1);
		}
	}

	public void capture_packages_Pcap4j(int dev_num, String filter, WebSocketSession session) {
		// Queue<String> packetJsonQue = new LinkedList<String>();// 用于抓包的存储和读取

		if (captureThread != null && captureThread.isHandleOpen()) {
			captureThread.closeThread();
		}
		// // send packet to client
		// if (sendPacketsThread != null) {
		// sendPacketsThread.kill_thread();
		// }
		// sendPacketsThread = new SendPacketThread(session, packetJsonQue);
		captureThread = new CaptureThread(dev_num, filter, session);
		captureThread.start();
	}

	class SendPacketThread extends Thread {

		private boolean stop = false;
		private WebSocketSession session = null;
		private Queue<String> packetJsonQue = null;

		public SendPacketThread(WebSocketSession session, Queue<String> packetJsonQue) {
			this.session = session;
			this.packetJsonQue = packetJsonQue;
		}

		public void kill_thread() {
			this.stop = true;
			packetJsonQue.clear();
		}

		@Override
		public void run() {
			// TODO Auto-generated method stub
			super.run();
			boolean isCthreadAlive = true;
			while (!stop) {
				if (packetJsonQue.isEmpty()) {
					System.out.println("empty");
					continue;
				}
				String packet_jsonString = packetJsonQue.poll();
				System.out.println("size of QUE: " + packetJsonQue.size() + packet_jsonString);
				if (packetJsonQue.size() >= 5000 && isCthreadAlive) {
					if (captureThread.isAlive() && captureThread.isHandleOpen()) {
						captureThread.closeThread();
						isCthreadAlive = false;
					}

					JSONObject tooManyPackets = new JSONObject();
					tooManyPackets.put("tag", "message");
					tooManyPackets.put("message", "后台抓包频繁（目前缓存已达5000+），存在内存溢出的风险。已抓取的包将继续推送至前台，后台已强制停止。建议更换过滤规则...");
					sendMessage(session, tooManyPackets.toJSONString());
				}
				sendMessage(session, packet_jsonString);
				try {
					Thread.sleep(100);// avoid sending too fast
				} catch (InterruptedException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
			System.out.println("thread stopped");
		}
	}

	class CaptureThread extends Thread {
		private int packets_num = 0;
		private Date start = null;
		private WebSocketSession session;
		private PcapHandle handle = null;
		private boolean stop = false;

		public CaptureThread(int dev_num, String filter, WebSocketSession session) {
			// TODO Auto-generated constructor stub
			this.session = session;

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
				start = new Date();
			} catch (PcapNativeException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			// handle = nif.openLive(snaplen, PromiscuousMode.NONPROMISCUOUS,
			// timeout);

			try {
				// 设置过滤器
				handle.setFilter(filter, BpfCompileMode.OPTIMIZE);

			} catch (PcapNativeException | NotOpenException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

		}

		public void closeThread() {
			if (isHandleOpen()) {
				stop = true;
				// handle.breakLoop();
				handle.close();
			}
		}

		public boolean isHandleOpen() {
			return (handle != null) && (handle.isOpen());
		}

		public void gotPacket(Packet packet) {
			System.out.println("------------------whole--------------------");
			System.out.println(packet);

			double time = (new Date().getTime() - start.getTime() + 0.0) / 1000;
			JSONObject packet_json = getPacketInfoJSON(packet, time);
			if (packet_json != null) {
				packet_json.put("ind", ++packets_num);
				sendMessage(session, packet_json.toJSONString());
			}
		}

		@Override
		public void run() {
			// TODO Auto-generated method stub
			super.run();

			// 监听
			System.out.println("开始抓包");
			while (!stop) {
				try {
					Packet packet = handle.getNextPacket();
					if (packet != null) {
						gotPacket(packet);
						Thread.sleep(100);
					}
				} catch (NotOpenException | InterruptedException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
			System.out.println(String.format("%s 抓包结束", this.getName()));
		}
	}
}
