package com.mysniffer.jtest;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;

import com.mysniffer.service.PackageService;

public class ServicesTest extends BasicTest {

	@Autowired
	PackageService pService;

	@Test
	public void test() {
		String pkg_hex_char = "t%.....4...,..E...k.@................PUK.r...hP.Dp....POST /res/v2?1524925478 HTTP/1.1..Host: rq.wh.cmcm.com..Accept: */*..Content-Length: 2517..Content-Type: application/x-www-form-urlencoded..Expect: 100-continue....";

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

			System.out.println(http.replace("..", "\n"));
		}
	}

}
