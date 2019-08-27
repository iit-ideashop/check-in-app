/// Stops the audio in any HTML audio elements with the given class name
function stopAudio(className) {
    let audioElements = document.getElementsByClassName(className);
    for (let audioElement of audioElements) {
        if (audioElement.pause) {
            audioElement.pause();
        }
    }
}

const socket = io();

$(function() {
    const reconnected = function () {
        $('#disconnect-alert').hide();
    };

    const disconnected = function () {
        $('#disconnect-alert').show();
    };

    socket.on('connect', reconnected);
    socket.on('reconnect', reconnected);

    socket.on('disconnect', disconnected);
    socket.on('reconnect_failed', disconnected);
    socket.on('connect_error', disconnected);

    socket.connect();

    /** @type{function(string): void} */
    window.navigatePOST = function(href) {
        // From https://stackoverflow.com/a/27208677
        let parts = href.split("?");
        let url = parts[0];
        let params = parts[1] ? parts[1].split('&') : [];
        let inputs = params.map(param => {
            let parts = param.split("=");
            return '<input type="hidden" name="' + parts[0] + '" value="' + parts[1] + '" />';
        }).join();
        $("body").append('<form action="'+url+'" method="post" id="poster">'+inputs+'</form>');
        $("#poster").submit();
    };

    $("a.POST").click(function (e) {
        e.stopPropagation();
        e.preventDefault();
        navigatePOST(this.href)
    });

    $('[data-href] tr').click(function(e) {
        let url = $(e.delegateTarget).data('href');
        console.log('Click! ' + url);
        window.location.href = url;
    });
});
