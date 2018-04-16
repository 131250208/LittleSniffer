package com.mysniffer.jtest;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;

import com.mysniffer.service.PackageService;

public class ServicesTest extends BasicTest {

	@Autowired
	PackageService pService;

	public void test() {
		pService.capture_packages();
	}

	@Test
	public void testRegex() {
		Pattern pattern = Pattern.compile("(.*?) (.*)");
		String str = "setdev 1";
		Matcher m = pattern.matcher(str);
		m.find();
		System.out.println(String.format("c: %s, p: %s", m.group(1), m.group(2)));
	}
}
