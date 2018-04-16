<%@ page language="java" import="java.util.*" pageEncoding="ISO-8859-1"%>
<%
	String path = request.getContextPath();
	String basePath = request.getScheme() + "://" + request.getServerName() + ":" + request.getServerPort()
			+ path + "/";
%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html>
<head>
<base href="<%=basePath%>">

<title>My JSP 'terminal.jsp' starting page</title>

<meta http-equiv="pragma" content="no-cache">
<meta http-equiv="cache-control" content="no-cache">
<meta http-equiv="expires" content="0">
<meta http-equiv="keywords" content="keyword1,keyword2,keyword3">
<meta http-equiv="description" content="This is my page">
<!--
	<link rel="stylesheet" type="text/css" href="styles.css">
	
	-->

<link
	href="https://cdn.bootcss.com/bootstrap/3.3.7/css/bootstrap.min.css"
	rel="stylesheet">

<link href="<%=basePath %>static/css/terminal.css" rel="stylesheet">
<script src="https://cdn.bootcss.com/jquery/2.1.1/jquery.min.js"></script>


</head>

<body>
	This is a terminal.
	<br>
	<div class="container-fluid">
		<div class="row" class="col-sm-12 col-xs-12">
			<input id="command">
		</div>
		<div class="row" class="col-sm-12 col-xs-12">
			<textarea id="terminal"  rows="37"></textarea>
		</div>
	</div>

	<script type="text/javascript">
		$(document).ready(function(){
			var ws = null;
			$(function() {
				$.ajax({
					url : "http://localhost:8080/LittleSniffer/login/4",
					success : function(result) {
						console.log(result);
						ws = new WebSocket("ws://localhost:8080/LittleSniffer/myHandler")
						ws.onmessage = function(msg) {
							var str = msg.data + "\n"
							$("textarea#terminal").append(str);
						}
					}
				});
			});
			
			$("input#command").keyup(function(event){
				if(event.which == 13){
					ws.send($(this).val());	
					$(this).val("");
				}
			});
		});
	</script>
</body>
</html>
