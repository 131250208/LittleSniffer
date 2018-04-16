package com.mysniffer.pojo;

public class Package {
	private int id;
	private double time;
	private String source;
	private String destination;
	private String protocol;
	private String information;

	@Override
	public String toString() {
		// TODO Auto-generated method stub
		return String.format("id: %d, time: %f, source: %s, destination: %s, protocol: %s, info: %s %n", id, time,
				source, destination, protocol, information);
	}

	public int getId() {
		return id;
	}

	public void setId(int id) {
		this.id = id;
	}

	public double getTime() {
		return time;
	}

	public void setTime(double time) {
		this.time = time;
	}

	public String getSource() {
		return source;
	}

	public void setSource(String source) {
		this.source = source;
	}

	public String getDestination() {
		return destination;
	}

	public void setDestination(String destination) {
		this.destination = destination;
	}

	public String getProtocol() {
		return protocol;
	}

	public void setProtocol(String protocol) {
		this.protocol = protocol;
	}

	public String getInformation() {
		return information;
	}

	public void setInformation(String information) {
		this.information = information;
	}
}
