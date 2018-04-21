package com.mysniffer.websocket;

import java.io.IOException;

import org.pcap4j.core.PacketListener;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.Packet;
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
	// // 在线用户列表
	// private static final Map<Integer, WebSocketSession> users;
	// // 用户标识
	// private static final String CLIENT_ID = "userId";
	//
	// static {
	// users = new HashMap<>();
	// }

	@Autowired
	PackageService packageService;

	@Override
	public void afterConnectionEstablished(WebSocketSession session) throws Exception {
		// Integer userId = getClientId(session);
		// if (userId != null) {
		// users.put(userId, session);
		//
		//
		// }
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

			// 初始化listener
			PacketListener listener = new PacketListener() {
				int num = 0;

				@Override
				public void gotPacket(Packet packet) {
					System.out.println(String.format("------------------%d--------------------", ++num));
					System.out.println("------------------header--------------------");
					System.out.println(packet.getHeader());
					System.out.println("------------------payload--------------------");
					System.out.println(packet.getPayload());
					System.out.println("------------------rawdata--------------------");
					System.out.println(packet.getRawData());
					System.out.println("------------------whole--------------------");
					System.out.println(packet);

					System.out.println(packet.getOuterOf(ArpPacket.class));
					System.out.println(packet.get(ArpPacket.class));
					System.out.println(packageService.getPacketInfoJSON(packet));

					// ObjectMapper mapper = new ObjectMapper();
					// String json_str = "";
					// try {
					// json_str = mapper.writerWithDefaultPrettyPrinter()
					// .writeValueAsString(packageService.getPacketInfoJSON(packet));
					// } catch (JsonProcessingException e) {
					// // TODO Auto-generated catch block
					// e.printStackTrace();
					// }

				}
			};

			packageService.capture_packages_Pcap4j(dev_num, filter, listener);
			break;
		default:
			break;
		}
	}

	// /**
	// * 发送信息给指定用户
	// *
	// * @param clientId
	// * @param message
	// * @return
	// */
	// public boolean sendMessageToUser(Integer clientId, TextMessage message) {
	// if (users.get(clientId) == null)
	// return false;
	// WebSocketSession session = users.get(clientId);
	// System.out.println("sendMessage:" + session);
	// if (!session.isOpen())
	// return false;
	// try {
	// session.sendMessage(message);
	// } catch (IOException e) {
	// e.printStackTrace();
	// return false;
	// }
	// return true;
	// }
	//
	// /**
	// * 广播信息
	// *
	// * @param message
	// * @return
	// */
	// public boolean sendMessageToAllUsers(TextMessage message) {
	// boolean allSendSuccess = true;
	// Set<Integer> clientIds = users.keySet();
	// WebSocketSession session = null;
	// for (Integer clientId : clientIds) {
	// try {
	// session = users.get(clientId);
	// if (session.isOpen()) {
	// session.sendMessage(message);
	// }
	// } catch (IOException e) {
	// e.printStackTrace();
	// allSendSuccess = false;
	// }
	// }
	//
	// return allSendSuccess;
	// }

	@Override
	public void handleTransportError(WebSocketSession session, Throwable exception) throws Exception {
		if (session.isOpen()) {
			session.close();
		}
		System.out.println("连接出错\n" + exception.toString());
		// users.remove(getClientId(session));
	}

	@Override
	public void afterConnectionClosed(WebSocketSession session, CloseStatus status) throws Exception {
		System.out.println("连接已关闭：" + status);
		// users.remove(getClientId(session));
	}

	@Override
	public boolean supportsPartialMessages() {
		return false;
	}

	/**
	 * 获取用户标识
	 * 
	 * @param session
	 * @return
	 */
	private Integer getClientId(WebSocketSession session) {
		Integer clientId = -1;
		try {
			clientId = Integer.parseInt(session.getId());
		} catch (Exception e) {
			return -1;
		}
		return clientId;
	}
}
