package com.mysniffer.controller;

import javax.servlet.http.HttpSession;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@RequestMapping("")
public class SocketController {

	@RequestMapping("/login/{userId}")
	public @ResponseBody String login(HttpSession session, @PathVariable("userId") Integer userId) {
		System.out.println("登录接口,userId=" + userId);
		session.setAttribute("userId", userId);
		System.out.println(session.getAttribute("userId"));

		return "success";
	}

}