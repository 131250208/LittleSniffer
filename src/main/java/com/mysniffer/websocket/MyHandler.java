package com.mysniffer.websocket;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.springframework.stereotype.Service;
import org.springframework.web.socket.CloseStatus;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.handler.TextWebSocketHandler;

@Service
public class MyHandler extends TextWebSocketHandler {
	// 在线用户列表
	private static final Map<Integer, WebSocketSession> users;
	// 用户标识
	private static final String CLIENT_ID = "userId";

	static {
		users = new HashMap<>();
	}

	@Override
	public void afterConnectionEstablished(WebSocketSession session) throws Exception {
		Integer userId = getClientId(session);
		if (userId != null) {
			users.put(userId, session);
			session.sendMessage(new TextMessage("成功建立socket连接"));
			// System.out.println(userId);
			// System.out.println(session);
		}
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
		String inp = message.getPayload();
		sendMessage(session, "client: " + inp);

		Pattern pattern = Pattern.compile("(.*?) (.*)");
		Matcher matcher = null;
		String command = null;
		String params = null;
		matcher = pattern.matcher(inp);
		if (matcher.find()) {
			command = matcher.group(1);
			params = matcher.group(2);

			switch (command) {
			case "setdev":
				try {
					Integer.parseInt(params.trim());
					sendMessage(session, "server: you have changed the dev.");
				} catch (Exception e) {
					// TODO: handle exception
					sendMessage(session, "server: please input an integer as the parameter.");
				}
				break;
			case "setfil":
				sendMessage(session, "server: you have set a new filter");
				break;
			default:
				sendMessage(session, "server: not a valid command.");
				break;
			}
		} else {
			sendMessage(session, "server: not a valid command.");
		}
	}

	/**
	 * 发送信息给指定用户
	 * 
	 * @param clientId
	 * @param message
	 * @return
	 */
	public boolean sendMessageToUser(Integer clientId, TextMessage message) {
		if (users.get(clientId) == null)
			return false;
		WebSocketSession session = users.get(clientId);
		System.out.println("sendMessage:" + session);
		if (!session.isOpen())
			return false;
		try {
			session.sendMessage(message);
		} catch (IOException e) {
			e.printStackTrace();
			return false;
		}
		return true;
	}

	/**
	 * 广播信息
	 * 
	 * @param message
	 * @return
	 */
	public boolean sendMessageToAllUsers(TextMessage message) {
		boolean allSendSuccess = true;
		Set<Integer> clientIds = users.keySet();
		WebSocketSession session = null;
		for (Integer clientId : clientIds) {
			try {
				session = users.get(clientId);
				if (session.isOpen()) {
					session.sendMessage(message);
				}
			} catch (IOException e) {
				e.printStackTrace();
				allSendSuccess = false;
			}
		}

		return allSendSuccess;
	}

	@Override
	public void handleTransportError(WebSocketSession session, Throwable exception) throws Exception {
		if (session.isOpen()) {
			session.close();
		}
		System.out.println("连接出错");
		users.remove(getClientId(session));
	}

	@Override
	public void afterConnectionClosed(WebSocketSession session, CloseStatus status) throws Exception {
		System.out.println("连接已关闭：" + status);
		users.remove(getClientId(session));
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
