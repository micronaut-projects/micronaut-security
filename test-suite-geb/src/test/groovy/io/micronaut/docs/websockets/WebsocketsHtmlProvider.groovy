package io.micronaut.docs.websockets

import io.micronaut.core.annotation.NonNull
import io.micronaut.core.annotation.Nullable;

class WebsocketsHtmlProvider {
    private final String serverUrl

    WebsocketsHtmlProvider(String serverUrl) {
        this.serverUrl = serverUrl.replaceAll("http://", "").replaceAll("https://", "")
    }

    @NonNull
    String html(@Nullable String jwt) {
        """<!DOCTYPE html>
                <html lang="en">
                <head>
                <meta charset="utf-8">
                <title>WebSockets Demo</title>
	<link rel="stylesheet" href="/assets/style.css">
        </head>
<body>
	<div id="page-wrapper">
		<h1>WebSockets Demo</h1>
                <div id="status">Connecting...</div>
		<ul id="messages"></ul>
                <form id="message-form" action="#" method="post">
                <textarea id="message" placeholder="Write your message here..." required></textarea>
			<button type="submit">Send Message</button>
                <button type="button" id="close">Close Connection</button>
		</form>
                </div>
	<script type="application/javascript">
        var serverUrl = "${serverUrl}";
        var jwt = "${jwt}"; 
        </script>
	<script src="/assets/app.js"></script>
        </body>
</html>"""
    }
}
