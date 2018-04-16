package com.mysniffer.jtest;

import java.util.List;

import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;

import com.mysniffer.mapper.PackagesMapper;
import com.mysniffer.pojo.Package;

public class MappersTest extends BasicTest {
	@Autowired
	PackagesMapper pMapper;

	@Test
	public void testGet_all_packages() {
		List<Package> packages = pMapper.get_all_packages();
		for (int i = 0; i < packages.size(); ++i) {
			System.out.println(packages.get(i));
		}
	}
}
