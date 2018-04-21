package com.mysniffer.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

@Controller
@RequestMapping("")
public class PagesController {

	@RequestMapping("/terminal")
	public ModelAndView getPageTerminal() {

		ModelAndView mav = new ModelAndView();
		mav.setViewName("terminal");
		return mav;
	}

	@RequestMapping("/userInterface")
	public ModelAndView getPageUserInterface() {

		ModelAndView mav = new ModelAndView();
		mav.setViewName("userInterface");
		return mav;
	}

}
