$(function() 
var socket = new io.Socket('ideashop-fedora',
	{port: 5000});
socket.connect();

socket.on('message',function(data)
	{window.location.href = data;}
);
)

