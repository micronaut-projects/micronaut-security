package io.micronaut.security.token.jwt.bearer

import io.micronaut.http.HttpMethod
import io.micronaut.http.HttpRequest
import io.micronaut.security.token.bearer.BearerTokenConfiguration
import io.micronaut.security.token.bearer.BearerTokenReader
import spock.lang.Shared
import spock.lang.Specification

class BearerTokenReaderSpec extends Specification {

    @Shared
    BearerTokenConfiguration config = Stub(BearerTokenConfiguration) {
        isEnabled() >> true
        getHeaderName() >> 'Authorization'
        getPrefix() >> 'Bearer'
    }

    @Shared
    BearerTokenReader bearerTokenReader = new BearerTokenReader(config)

    def extractTokenFromAuthorization() {
        expect:
        bearerTokenReader.extractTokenFromAuthorization('Bearer XXX').get() == 'XXX'

        and:
        !bearerTokenReader.extractTokenFromAuthorization('BearerXXX').isPresent()

        and:
        !bearerTokenReader.extractTokenFromAuthorization('XXX').isPresent()

        and: 'the prefix comparison is case insensitive'
        bearerTokenReader.extractTokenFromAuthorization('bEaReR XXX').get() == 'XXX'

        and: 'a prefix-only header yields no token'
        !bearerTokenReader.extractTokenFromAuthorization('Bearer').isPresent()

        and: 'a prefix followed only by a space yields an empty token'
        bearerTokenReader.extractTokenFromAuthorization('Bearer ').get() == ''
    }

    def "a very long token round-trips unchanged"() {
        given:
        String token = 'eyJhbGciOiJIUzI1NiJ9.' + ('abcdefghijklmnopqrstuvwxyz0123456789' * 200) + '.signature'
        def request = HttpRequest.create(HttpMethod.GET, '/').header('Authorization', 'Bearer ' + token)

        expect:
        bearerTokenReader.findToken(request).get() == token
    }

    def "if authorization header not present returns empty"() {
        given:
        def request = HttpRequest.create(HttpMethod.GET, '/')

        expect:
        !bearerTokenReader.findToken(request).isPresent()
    }

    def "findTokenAtAuthorizationHeader parses header correctly"() {
        given:
        def request = HttpRequest.create(HttpMethod.GET, '/').header('Authorization', 'Bearer XXX')

        expect:
        bearerTokenReader.findToken(request).get() == 'XXX'
    }
}
