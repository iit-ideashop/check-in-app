/// Stops the audio in any HTML audio elements with the given class name
function stopAudio(className) {
    let audioElements = document.getElementsByClassName(className);
    for (let audioElement of audioElements) {
        if (audioElement.pause) {
            audioElement.pause();
        }
    }
}

socket = io();

$(function() {
    const reconnected = function () {
        $('#disconnect-alert').hide();
    };

    const disconnected = function () {
        $('#disconnect-alert').show();
    };

    socket.on('connect', reconnected);
    socket.on('reconnect', reconnected);

    socket.on('reconnect_failed', disconnected);
    socket.on('connect_error', disconnected);

    socket.connect();
});