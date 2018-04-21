package com.mysniffer.jtest;

import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;

import com.mysniffer.service.PackageService;

public class ServicesTest extends BasicTest {

	@Autowired
	PackageService pService;

	@Test
	public void test() {
		// try {
		// pService.capture_packages_Pcap4j();
		// } catch (Exception e) {
		// // TODO: handle exception
		// System.out.println(e);
		// }

		String string = pService.getDevicesList();
		System.out.println(string);
	}

}
