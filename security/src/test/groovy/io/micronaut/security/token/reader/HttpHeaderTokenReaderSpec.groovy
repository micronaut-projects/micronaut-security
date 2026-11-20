package io.micronaut.security.token.reader

import io.micronaut.http.HttpMethod
import io.micronaut.http.HttpRequest
import spock.lang.Shared
import spock.lang.Specification

class HttpHeaderTokenReaderSpec extends Specification {

    @Shared
    HttpHeaderTokenReader tokenReader = new StubHttpHeaderTokenReader('Header', 'Prefix')

    @Shared
    HttpHeaderTokenReader bearerTokenReader = new StubHttpHeaderTokenReader('Authorization', 'Bearer')

    def "findToken parsing is case insensitive"() {
        given:
        def request = HttpRequest.create(HttpMethod.GET, '/').header('hEaDeR', 'PrEfIx XXX')

        expect:
        tokenReader.findToken(request).get() == 'XXX'
    }

    void "extractTokenFromAuthorization #description"(String authorization, Optional<String> expected, String description) {
        expect:
        bearerTokenReader.extractTokenFromAuthorization(authorization) == expected

        where:
        authorization | expected         | description
        'Bearer x'    | Optional.of('x') | 'accepts an exact prefix'
        'bEaReR x'    | Optional.of('x') | 'accepts a mixed-case prefix'
        'Bearer '     | Optional.of('')  | 'yields an empty token when only the prefix and a space are present'
        'Bearerx'     | Optional.empty() | 'rejects a prefix not followed by a space'
        'Bearer'      | Optional.empty() | 'rejects a prefix-only header with no token'
        'Basic x'     | Optional.empty() | 'rejects a different prefix'
    }

    void "a prefix ending with a space is not followed by another space"() {
        given:
        HttpHeaderTokenReader reader = new StubHttpHeaderTokenReader('Authorization', 'Bearer ')

        expect:
        reader.extractTokenFromAuthorization('Bearer x') == Optional.of('x')
        reader.extractTokenFromAuthorization('Bearerx') == Optional.empty()
    }

    void "an empty prefix returns the whole header value"() {
        given:
        HttpHeaderTokenReader reader = new StubHttpHeaderTokenReader('X-Api-Token', prefix)

        expect:
        reader.extractTokenFromAuthorization('XXX') == Optional.of('XXX')
        reader.extractTokenFromAuthorization('') == Optional.of('')

        where:
        prefix << ['', null]
    }

    private class StubHttpHeaderTokenReader extends HttpHeaderTokenReader {
        String headerName
        String prefix

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
