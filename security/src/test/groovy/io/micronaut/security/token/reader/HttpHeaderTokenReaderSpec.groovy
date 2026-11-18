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
        authorization    | expected                | description
        'Bearer x'       | Optional.of('x')        | 'accepts an exact prefix'
        'bEaReR x'       | Optional.of('x')        | 'accepts a mixed-case prefix'
        'BEARER x'       | Optional.of('x')        | 'accepts an upper-case prefix'
        'Bearerx'        | Optional.empty()        | 'rejects a prefix not followed by a space'
        'Bearer'         | Optional.empty()        | 'rejects a prefix-only header with no token'
        'Bear'           | Optional.empty()        | 'rejects a header shorter than the prefix'
        ''               | Optional.empty()        | 'rejects an empty header'
        'Bearer '        | Optional.of('')         | 'yields an empty token when only the prefix and a space are present'
        'Bearer  x'      | Optional.of(' x')       | 'consumes exactly one space after the prefix'
        'Bearer x y'     | Optional.of('x y')      | 'keeps the rest of the header untouched'
        'Basic x'        | Optional.empty()        | 'rejects a different prefix'
        'Bearer\tx'      | Optional.empty()        | 'rejects a tab as the separator'
        ' Bearer x'      | Optional.empty()        | 'rejects leading whitespace before the prefix'
        'x Bearer y'     | Optional.empty()        | 'rejects a prefix that is not at the start'
    }

    void "prefix matching does not fold look-alike characters through upper case"(String prefix, String authorization, Optional<String> expected) {
        given:
        HttpHeaderTokenReader reader = new StubHttpHeaderTokenReader('Authorization', prefix)

        expect:
        reader.extractTokenFromAuthorization(authorization) == expected

        where:
        prefix  | authorization           | expected
        'Basic' | 'BASIC x'               | Optional.of('x')
        'Basic' | 'Ba\u017F\u0131c x'     | Optional.empty() // long s and dotless i upper-case to S and I
        'Token' | 'To\u212Aen x'          | Optional.of('x') // the Kelvin sign lower-cases to k, as it did before
        'Tökén' | 'TÖKÉN x'               | Optional.of('x')
    }

    void "a prefix ending with a space is not followed by another space"() {
        given:
        HttpHeaderTokenReader reader = new StubHttpHeaderTokenReader('Authorization', 'Bearer ')

        expect:
        reader.extractTokenFromAuthorization('Bearer x') == Optional.of('x')
        reader.extractTokenFromAuthorization('Bearerx') == Optional.empty()
    }

    void "a very long token round-trips unchanged"() {
        given:
        String token = (('a'..'z') + ('A'..'Z') + ('0'..'9') + ['-', '_', '.']).join('') * 100
        def request = HttpRequest.create(HttpMethod.GET, '/').header('Authorization', 'Bearer ' + token)

        expect:
        token.length() > 6000
        bearerTokenReader.findToken(request).get() == token
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
