<!DOCTYPE html>
<html>

<head>
  <title>SCN WEB-Interface</title>
	<meta charset="UTF-8" />
	<link rel="icon" type="image/vnd.microsoft.icon" href="/static/favicon.ico"/>
	<script type="text/javascript" src="/static/mainjs.js"></script>
	<link rel="stylesheet" type="text/css" src="/static/maincss.css"/>

</head>
<body>
<header>
	<a href="/friends">Switch to friends<a>
	<input type="button" value="print" onClick="javascript:window.print()">
</header>

<main>
<table>
	<tr>
		<td class="sidebar">
			<nav>
				<a href="#" onclick="list_servers()">List server</a> <br>
%if server!=None:
					<a href="#" onclick="servermanagement()">List Names</a> <br>
					<a href="#" onclick="servermanagement()">Register Name</a> <br>
					<a href="#" onclick="servermanagement()">Delete Name</a> <br>
					<a href="#" onclick="servermanagement()">Get Server Info</a> <br>
					<a href="#" onclick="servermanagement()">Get Server Certificate</a> <br>
%end
					<a href="">Reload</a>
		</td>
		<td class="content">
			<div id="maincontent">
		</td>
	</tr>
</table>
</main>
	
</body>
</html>
