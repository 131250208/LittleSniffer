/**
 * 
 */
var ws = null;

function connectWebSocket(){
	$.ajax({
		url : "http://localhost:8080/LittleSniffer/login/4",
		success : function(result) {
			console.log(result);
			ws = new WebSocket("ws://localhost:8080/LittleSniffer/UIHandler")
			ws.onmessage = function(msg) {
				var str = msg.data + "\n"
//				alert(str);
				dealJsonMsg(str);
			}
		}
	});
};

$(document).ready(function() {
	new connectWebSocket();

	$("button#capture").bind("click", function() {
		startCapture();
	});

	$("input#filter").keydown(function(event) {
		if (event.which == 13) {
			new MyWebSocket();
			startCapture();
			$(this).val("");
		}
	});
});

function startCapture() {
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
}


function dealJsonMsg(msg) {
	var job = eval('(' + msg + ')');
	var tag = job.tag;

	switch (tag) {
	case "devices_list":
		var devices = job.devices;
		for (var i = 0; i < devices.length; ++i) {
			var name = devices[i].name;
			var opt = $('<option value="' + i + '">' + name + '</option>');
			$('select.selectpicker').append(opt);
		}

		$('select.selectpicker').selectpicker('render');
		$('select.selectpicker').selectpicker('refresh');
		break;
	}
}