package com.mysniffer.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

@Controller
@RequestMapping("")
public class NewsController {

	@RequestMapping("/terminal")
	public ModelAndView get_search_page() {

		ModelAndView mav = new ModelAndView();
		mav.setViewName("terminal");
		return mav;
	}

}
