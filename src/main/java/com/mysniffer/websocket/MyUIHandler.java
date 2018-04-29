package com.mysniffer.websocket;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.socket.CloseStatus;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.handler.TextWebSocketHandler;

import com.alibaba.fastjson.JSONObject;
import com.mysniffer.service.PackageService;

@Service
public class MyUIHandler extends TextWebSocketHandler {

	@Autowired
	PackageService packageService;

	@Override
	public void afterConnectionEstablished(WebSocketSession session) throws Exception {
		sendMessage(session, packageService.getDevicesList());
	}

	private void sendMessage(WebSocketSession session, String msg) {
		try {
			session.sendMessage(new TextMessage(msg));
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
	}

	@Override
	public void handleTextMessage(WebSocketSession session, TextMessage message) {
		// ...
		String jsonString = message.getPayload();
		System.out.println(jsonString);

		JSONObject job = JSONObject.parseObject(jsonString);
		String tag = job.getString("tag");
		switch (tag) {
		case "call_starCapture":
			int dev_num = Integer.parseInt(job.getString("dev_num"));
			String filter = job.getString("filter");
			// start capturing
			packageService.capture_packages_Pcap4j(dev_num, filter, session);
			break;
		default:
			break;
		}
	}

	@Override
	public void handleTransportError(WebSocketSession session, Throwable exception) throws Exception {
		if (session.isOpen()) {
			session.close();
		}
		System.out.println("连接出错\n" + exception.toString());
	}

	@Override
	public void afterConnectionClosed(WebSocketSession session, CloseStatus status) throws Exception {
		System.out.println("连接已关闭：" + status);
	}

	@Override
	public boolean supportsPartialMessages() {
		return false;
	}
}
