package com.mysniffer.service;

import org.springframework.web.socket.WebSocketSession;

public interface PackageService {

	public String getDevicesList();

	public void capture_packages_Pcap4j(int dev_num, String filter, WebSocketSession session);
}
