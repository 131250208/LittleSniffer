<%@ page language="java" import="java.util.*" pageEncoding="UTF-8"%>
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
<!-- 自定义 -->
<link href="<%=basePath%>static/css/userInterface.css" rel="stylesheet">

<!-- 框架 -->
<script src="<%=basePath%>static/js/jquery-3.3.1.min.js"></script>
<link rel="stylesheet" href="<%=basePath%>static/css/bootstrap.min.css">
<link rel="stylesheet"
	href="<%=basePath%>static/css/bootstrap-select.min.css">
<script src="<%=basePath%>static/js/bootstrap.min.js"></script>
<script src="<%=basePath%>static/js/bootstrap-select.min.js"></script>



</head>

<body background="<%=basePath%>static/images/bg.jpg">
	<div class="container-fluid">
		<form role="form" name="add_editor_type" novalidate
			onkeydown="if(event.keyCode==13){return false;}">
			<div class="container">
				<div class="row" class="col-sm-12 col-xs-12">
					<div class=" col-sm-3 col-xs-12">
						<select id="devices_selector" class="selectpicker form-control"
							data-width="100%" required>
						</select>
					</div>

					<div class="col-sm-8 col-xs-12 ">
						<input type="text" id="filter" placeholder="filter"
							class="form-control">
					</div>
					<div class="col-sm-1 col-xs-12">
						<button type="button" id="capture" class="btn btn-primary"
							>capture</button>
					</div>
				</div>
				<div id="filter_div" class="collapse">
					<div class="row" class="col-sm-12 col-xs-12">
						<div class="col-sm-3 col-xs-12">
							<select id="type_filter_selector"
								class="selectpicker form-control" data-width="100%" multiple>
								<option>ARP</option>
								<option>UDP</option>
								<option>TCP</option>
								<option>ICMP</option>
								<option>IGMP</option>
							</select>
						</div>
						<div class="col-sm-3 col-xs-12">
							<input type="text" name="src_ip" placeholder="source ip address"
								class="form-control">
						</div>
						<div class="col-sm-1 col-xs-12">
							<input type="text" name="src_port" placeholder="port"
								class="form-control">
						</div>
						<div class="col-sm-3 col-xs-12">
							<input type="text" name="dest_ip"
								placeholder="destination ip address" class="form-control">
						</div>
						<div class="col-sm-1 col-xs-12">
							<input type="text" name="dest_port" placeholder="port"
								class="form-control">
						</div>
						<div class="col-sm-1 col-xs-12">
							<button type="button" id="filter" class="btn btn-info">&nbsp;&nbsp;filter&nbsp;&nbsp;</button>
						</div>
					</div>
				</div>
			</div>
		</form>
		<div class="container" id="basic_info">
			<div class="table-responsive">
				<table class="table table-striped table_head">
					<thead>
						<tr>
							<th>No.</th>
							<th>Time</th>
							<th>Source</th>
							<th>Destination</th>
							<th>Protocol</th>
							<th>Length</th>
							<th>Info</th>
						</tr>
					</thead>
				</table>
			</div>
			<div class="table-responsive div_table_body">
				<table class="table table-striped table_body table-hover">
					<thead>
						<tr>
							<th>No.</th>
							<th>Time</th>
							<th>Source</th>
							<th>Destination</th>
							<th>Protocol</th>
							<th>Length</th>
							<th>Info</th>
						</tr>
					</thead>
					<tbody>
						<c:forEach var="i" begin="1" end="15">
							<tr>
								<td>&nbsp;</td>
								<td>&nbsp;</td>
								<td>&nbsp;</td>
								<td>&nbsp;</td>
								<td>&nbsp;</td>
								<td>&nbsp;</td>
								<td>&nbsp;</td>
							</tr>
						</c:forEach>
					</tbody>
				</table>
			</div>
		</div>

		<div class="container" id="detail_info">
			<div class="panel-group" id="accordion">
				<div class="panel panel-default" id="panel-1">
					<div class="panel-heading">
						<h4 class="panel-title" id="panel-title-1">
							<a data-toggle="collapse" data-parent="#accordion"
								href="#collapseOne"></a>
						</h4>
					</div>
					<div id="collapseOne" class="panel-collapse collapse">
						<div class="panel-body" id="panel-body-1"></div>
					</div>
				</div>
				<div class="panel panel-default" id="panel-2">
					<div class="panel-heading">
						<h4 class="panel-title" id="panel-title-2">
							<a data-toggle="collapse" data-parent="#accordion"
								href="#collapseTwo"> 点击我进行展开，再次点击我进行折叠。第 2 部分 </a>
						</h4>
					</div>
					<div id="collapseTwo" class="panel-collapse collapse">
						<div class="panel-body" id="panel-body-2"></div>
					</div>
				</div>
				<div class="panel panel-default" id="panel-3">
					<div class="panel-heading">
						<h4 class="panel-title" id="panel-title-3">
							<a data-toggle="collapse" data-parent="#accordion"
								href="#collapseThree"> 点击我进行展开，再次点击我进行折叠。第 3 部分 </a>
						</h4>
					</div>
					<div id="collapseThree" class="panel-collapse collapse">
						<div class="panel-body" id="panel-body-3"></div>
					</div>
				</div>
				<div class="panel panel-default" id="panel-3">
					<div class="panel-heading">
						<h4 class="panel-title" id="panel-title-4">
							<a data-toggle="collapse" data-parent="#accordion"
								href="#collapseFour"> 点击我进行展开，再次点击我进行折叠。第 4 部分 </a>
						</h4>
					</div>
					<div id="collapseFour" class="panel-collapse collapse">
						<div class="panel-body" id="panel-body-4"></div>
					</div>
				</div>
			</div>
		</div>

		<div class="container">
			<textarea rows="12" id="rawdata_hex"></textarea>
		</div>
	</div>
</body>

<script type="text/javascript"
	src="<%=basePath%>static/js/userInterface.js">

</script>
</html>
