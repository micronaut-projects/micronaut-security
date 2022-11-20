package io.micronaut.security.testutils

import io.micronaut.http.HttpRequest
import io.micronaut.http.MediaType
import io.micronaut.http.MutableHttpRequest

final class BrowserHttpRequest {

    private BrowserHttpRequest() {

    }

    static <T> MutableHttpRequest<T> GET(String uri) {
        decorate(HttpRequest.GET(uri))
    }

    private static <T> MutableHttpRequest<T> decorate(MutableHttpRequest<T> request) {
        request.header("Connection","keep-alive")
                .header("Accept-Encoding", "gzip, deflate")
                .header("Accept-Language", "en-GB,en;q=0.9")
                .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
                .header("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15")
    }
}
