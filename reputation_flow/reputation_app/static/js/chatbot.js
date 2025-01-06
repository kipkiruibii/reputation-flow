const chatbotIframe = document.getElementById('chatbot-iframe');
const chatbotIcon = document.getElementById('chatbot-icon-rs');

function toggleIframe() {
    var iframe = document.getElementById('chatbot-iframe');
    // Check if iframe is currently hidden
    if (iframe.style.display === "none" || iframe.style.display === "") {
        iframe.style.display = "block";  // Show the iframe
        iframe.style.visibility = "visible";  // Ensure visibility
        iframe.style.opacity = "1";  // Make it fully visible
    } else {
        iframe.style.display = "none";  // Hide the iframe
        iframe.style.visibility = "hidden";  // Hide visibility
        iframe.style.opacity = "0";  // Make it invisible
    }
}
