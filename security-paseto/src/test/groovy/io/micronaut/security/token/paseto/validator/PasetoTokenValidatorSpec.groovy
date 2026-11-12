package io.micronaut.security.token.paseto.validator

import dev.paseto.jpaseto.Paseto
import dev.paseto.jpaseto.PasetoException
import dev.paseto.jpaseto.PasetoParser
import io.micronaut.security.authentication.Authentication
import reactor.core.publisher.Mono
import spock.lang.Specification

class PasetoTokenValidatorSpec extends Specification {

    void "validateToken emits authentication when parser and factory accept token"() {
        given:
        Paseto token = Mock()
        PasetoParser parser = Mock()
        PasetoAuthenticationFactory authenticationFactory = Mock()
        PasetoTokenValidator validator = new PasetoTokenValidator(authenticationFactory, parser)
        Authentication authentication = Authentication.build('sherlock')

        when:
        Authentication result = Mono.from(validator.validateToken('token', null)).block()

        then:
        result == authentication
        1 * parser.parse('token') >> token
        1 * authenticationFactory.createAuthentication(token) >> Optional.of(authentication)
    }

    void "validateToken completes empty when parser rejects token"() {
        given:
        PasetoParser parser = Mock()
        PasetoAuthenticationFactory authenticationFactory = Mock()
        PasetoTokenValidator validator = new PasetoTokenValidator(authenticationFactory, parser)

        when:
        Authentication result = Mono.from(validator.validateToken('bad-token', null)).block()

        then:
        result == null
        1 * parser.parse('bad-token') >> { throw new PasetoException('bad token') }
        0 * authenticationFactory._
    }
}
