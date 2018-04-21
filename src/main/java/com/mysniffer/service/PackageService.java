package com.mysniffer.service;

import org.pcap4j.core.PacketListener;
import org.pcap4j.packet.Packet;

public interface PackageService {

	public String getDevicesList();

	public String getPacketInfoJSON(Packet packet);

	public void capture_packages_Pcap4j(int dev_num, String filter, PacketListener listener);
}
