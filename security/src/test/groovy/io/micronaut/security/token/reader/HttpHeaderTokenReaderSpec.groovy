package io.micronaut.security.token.reader

import io.micronaut.http.HttpMethod
import io.micronaut.http.HttpRequest
import spock.lang.Shared
import spock.lang.Specification

class HttpHeaderTokenReaderSpec extends Specification {

    @Shared
    HttpHeaderTokenReader tokenReader = new StubHttpHeaderTokenReader('Header', 'Prefix');

    def "findToken parsing is case insensitive"() {
        given:
        def request = HttpRequest.create(HttpMethod.GET, '/').header('hEaDeR', 'PrEfIx XXX')

        expect:
        tokenReader.findToken(request).get() == 'XXX'
    }

    private class StubHttpHeaderTokenReader extends HttpHeaderTokenReader {
        String headerName;
        String prefix;

        StubHttpHeaderTokenReader(String headerName, String prefix) {
            this.headerName = headerName
            this.prefix = prefix
        }

        @Override
        String getHeaderName() {
            return headerName
        }

        @Override
        String getPrefix() {
            return prefix
        }
    }
}
