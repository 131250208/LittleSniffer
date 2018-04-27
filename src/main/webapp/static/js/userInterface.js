/**
 * 
 */

$(document).ready(function() {
	$("div#panel-1").hide();
	$("div#panel-2").hide();
	$("div#panel-3").hide();
	$("div#panel-4").hide();

	new connectWebSocket();

	$("button#capture").bind("click", function() {
		startCapture();
	});
	
	$("button#filter").bind("click", function() {
		filter_all();
	});

	$("input#filter").keyup(function(event) {
		if (event.which == 13) {
			startCapture();
			$(this).val("");
		}
	});
});

var start_filter = 0;
var types= "";
var src_ip_fil = "";
var src_port_fil = "";
var dest_ip_fil = "";
var dest_port_fil = "";

function filter(tr){
	var type = tr.data("type");
	var src_ip = tr.data("src_ip");
	var src_port = tr.data("src_port");
	var dest_ip = tr.data("dest_ip");
	var dest_port = tr.data("dest_port");
	
	var type_included = 0;
	for(var j = 0; j < types.length; ++j){
		if(types[j] == type){
			type_included = 1;
		}
	}
	if (type_included == 0||
			src_ip_fil != "" && src_ip_fil != src_ip||
			src_port_fil != "" && src_port_fil != src_port||
			dest_ip_fil != "" && dest_ip_fil != dest_ip||
			dest_port_fil != "" && dest_port_fil != dest_port){
		tr.hide();
	}else{
		tr.show();
	}
}

function filter_all(){
	types= $("select#type_filter_selector").val();
	src_ip_fil = $("input[name='src_ip']").val();
	src_port_fil = $("input[name='src_port']").val();
	dest_ip_fil = $("input[name='dest_ip']").val();
	dest_port_fil = $("input[name='dest_port']").val();
	
	start_filter = 1;// inform func dealJson to filter new packets
	
	$("div#basic_info table.table_body tbody tr").each(function(){
		filter($(this));
	});
}

var ws = null;

function connectWebSocket(){
	$.ajax({
		url : "http://localhost:8080/LittleSniffer/login/4",
		success : function(result) {
			console.log(result);
			ws = new WebSocket("ws://localhost:8080/LittleSniffer/UIHandler")
			ws.onmessage = function(msg) {
				var str = msg.data + "\n"
				dealJsonMsg(str);
			}
		}
	});
};

function startCapture() {
	$("div#basic_info table.table_body tbody").empty();
	
	var dev_num = $("#devices_selector").val();
	var filter = $("input#filter").val();
	if (filter == "") {
		alert("please input your filter");
		return;
	}
	var command = {
		"tag" : "call_starCapture",
		"dev_num" : dev_num,
		"filter" : filter,
	};

	ws.send(JSON.stringify(command));
	$("div#filter_div").collapse("show");
}

function dealJsonMsg(msg) {
	var job = eval('(' + msg + ')');
	var tag = job.tag;

	switch (tag) {
	case "devices_list":
		var devices = job.devices;
		var select = $('select#devices_selector');
		for (var i = 0; i < devices.length; ++i) {
			var name = devices[i].name;
			var opt = $('<option value="' + i + '">' + name + '</option>');
			select.append(opt);
		}

		select.selectpicker('render');
		select.selectpicker('refresh');
		break;
	case "packet":
		var tbody = $("div#basic_info table.table_body tbody");
		var html = "<tr>" +
						"<td>"+ job.ind +"</td>" +
						"<td>"+ job.time +"</td>" +
						"<td>"+ job.src_addr +"</td>" + 
						"<td>"+ job.dest_addr +"</td>" +
						"<td>"+ job.type +"</td>" +
						"<td>"+ job.length +"</td>" +
						"<td>"+ job.info +"</td>" +
					"</tr>";
		var tr = $(html);
		
		var panel_1 = $("div#panel-1");
		var panel_2 = $("div#panel-2");
		var panel_3 = $("div#panel-3");
		var panel_4 = $("div#panel-4");
		
		var panel_title_1 = $("h4#panel-title-1 > a");
		var panel_title_2 = $("h4#panel-title-2 > a");
		var panel_title_3 = $("h4#panel-title-3 > a");
		var panel_title_4 = $("h4#panel-title-4 > a");
		
		var panel_body_1 = $("div#panel-body-1");
		var panel_body_2 = $("div#panel-body-2");
		var panel_body_3 = $("div#panel-body-3");
		var panel_body_4 = $("div#panel-body-4");
		
		tr.bind("click", function(){
			$("textarea#rawdata_hex").val(job.pkg_hex);
			
			panel_1.show();
			panel_title_1.empty();
			panel_title_1.append("Ethernet II");
			panel_body_1.empty();
			panel_body_1.append(job.eth_header);
			
			switch(job.type){
			case "ARP":				
				panel_2.show();
				panel_3.hide();
				panel_4.hide();
				
				panel_title_2.empty();
				panel_title_2.append("ARP Header");
				panel_body_2.empty();
				panel_body_2.append(job.arp_header);
				break;
			case "UDP":
			case "TCP":
			case "ICMP":
				panel_2.show();
				panel_3.show();
				panel_4.show();
				
				panel_title_2.empty();
				panel_title_2.append("IP Header");
				panel_body_2.empty();
				panel_body_2.append(job.ipv4_header);
				
				panel_title_3.empty();
				panel_title_3.append(job.type + " Header");
				panel_body_3.empty();
				panel_body_3.append(job.special_header);
				
				panel_title_4.empty();
				panel_title_4.append("Data");
				panel_body_4.empty();
				panel_body_4.append(job.data);
				break;
			}
		});
		
		tr.data("type", job.type);
		tr.data("src_ip", job.src_ip);
		tr.data("dest_ip", job.dest_ip);
		tr.data("src_port", job.src_port);
		tr.data("dest_port", job.dest_port);
		
		tbody.append(tr);
		if(start_filter){
			filter(tr);
		}
		break;
	}
}