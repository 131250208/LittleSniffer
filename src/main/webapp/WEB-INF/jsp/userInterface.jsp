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
<link rel="stylesheet"
	href="<%=basePath%>static/css/bootstrap.min.css">
<link rel="stylesheet"
	href="<%=basePath%>static/css/bootstrap-select.min.css">
<script
	src="<%=basePath%>static/js/bootstrap.min.js"></script>
<script
	src="<%=basePath%>static/js/bootstrap-select.min.js"></script>



</head>

<body background="<%=basePath%>static/images/bg.jpg">
	<div class="container-fluid">
		<form role="form" name="add_editor_type" novalidate onkeydown="if(event.keyCode==13){return false;}">
			<div class="container">
				<div class="row" class="col-sm-12 col-xs-12">

					<div class=" col-sm-2 col-xs-12">
						<select id="devices_selector" class="selectpicker form-control" data-width="100%"
							required>

						</select>
					</div>

					<div class="col-sm-9 col-xs-12 ">
						<input type="text" id="filter" placeholder="filter"
							class="form-control">
					</div>
					<div class="col-sm-1 col-xs-12">
						<button type="button" id="capture" class="btn btn-primary">capture</button>
					</div>
				</div>
			</div>
		</form>
		<div class="container" id="basic_info">
			<div class="table-responsive">
				<table class="table table-striped">
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
			<div class="table-responsive">
				<table class="table table-striped">
					<tbody>
						<c:forEach var="i" begin="1" end="25">
							<tr>
								<td>${i}</td>
								<td>151563.</td>
								<td>192.35.22.21</td>
								<td>235.265.789.452</td>
								<td>ARP</td>
								<td>890</td>
								<td>Standard query 0x0549 ANY DESKTOP-5JC0H3O</td>
							</tr>
						</c:forEach>
					</tbody>
				</table>
			</div>
		</div>

		<div class="container" id="detail_info">
			<div class="panel-group" id="accordion">
				<div class="panel panel-default">
					<div class="panel-heading">
						<h4 class="panel-title">
							<a data-toggle="collapse" data-parent="#accordion"
								href="#collapseOne"> 点击我进行展开，再次点击我进行折叠。第 1 部分 </a>
						</h4>
					</div>
					<div id="collapseOne" class="panel-collapse collapse">
						<div class="panel-body">
							Nihil anim keffiyeh helvetica,<br /> craft beer labore wes
							anderson cred nesciunt sapiente ea proident.<br /> Ad vegan
							excepteur butcher vice lomo.
						</div>
					</div>
				</div>
				<div class="panel panel-default">
					<div class="panel-heading">
						<h4 class="panel-title">
							<a data-toggle="collapse" data-parent="#accordion"
								href="#collapseTwo"> 点击我进行展开，再次点击我进行折叠。第 2 部分 </a>
						</h4>
					</div>
					<div id="collapseTwo" class="panel-collapse collapse">
						<div class="panel-body">Nihil anim keffiyeh helvetica, craft
							beer labore wes anderson cred nesciunt sapiente ea proident. Ad
							vegan excepteur butcher vice lomo.</div>
					</div>
				</div>
				<div class="panel panel-default">
					<div class="panel-heading">
						<h4 class="panel-title">
							<a data-toggle="collapse" data-parent="#accordion"
								href="#collapseThree"> 点击我进行展开，再次点击我进行折叠。第 3 部分 </a>
						</h4>
					</div>
					<div id="collapseThree" class="panel-collapse collapse">
						<div class="panel-body">Nihil anim keffiyeh helvetica, craft
							beer labore wes anderson cred nesciunt sapiente ea proident. Ad
							vegan excepteur butcher vice lomo.</div>
					</div>
				</div>
				<div class="panel panel-default">
					<div class="panel-heading">
						<h4 class="panel-title">
							<a data-toggle="collapse" data-parent="#accordion"
								href="#collapseFour"> 点击我进行展开，再次点击我进行折叠。第 4 部分 </a>
						</h4>
					</div>
					<div id="collapseFour" class="panel-collapse collapse">
						<div class="panel-body">Nihil anim keffiyeh helvetica, craft
							beer labore wes anderson cred nesciunt sapiente ea proident. Ad
							vegan excepteur butcher vice lomo.</div>
					</div>
				</div>
			</div>
		</div>

		<div class="container">
			<textarea rows="12" id="bindata"></textarea>
		</div>
	</div>
</body>

<script type="text/javascript" src="<%=basePath%>static/js/userInterface.js">

</script>
</html>
