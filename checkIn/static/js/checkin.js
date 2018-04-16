/// Stops the audio in any HTML audio elements with the given class name
function stopAudio(className) {
    let audioElements = document.getElementsByClassName(className);
    for (let audioElement of audioElements) {
        if (audioElement.pause) {
            audioElement.pause();
        }
    }
}

$(function() {
});