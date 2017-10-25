$(function() {
    localStorage.debug = '*';

    var socket = io();

    socket.connect();

    socket.on('go', function (data) {
        window.location.href = data.to;
    });
});

