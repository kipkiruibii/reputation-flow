
const chatbotIframe = document.getElementById('chatbot-iframe');
const chatbotIcon = document.getElementById('chatbot-icon-rs');

function toggleIframe() {
    if (chatbotIframe.style.display === 'none') {
        chatbotIframe.style.display = 'flex'; // Show iframe
    } else {
        chatbotIframe.style.display = 'none'; // Hide iframe
    }
}

