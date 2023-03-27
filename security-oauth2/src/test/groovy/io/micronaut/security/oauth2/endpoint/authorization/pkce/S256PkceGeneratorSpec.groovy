package io.micronaut.security.oauth2.endpoint.authorization.pkce

import io.micronaut.context.BeanContext
import io.micronaut.context.annotation.Property
import io.micronaut.core.util.StringUtils
import io.micronaut.test.extensions.spock.annotation.MicronautTest
import jakarta.inject.Inject
import spock.lang.Specification

@MicronautTest(startApplication = false)
class S256PkceGeneratorSpec extends Specification {
    @Inject
    BeanContext beanContext

    void "code verifier does not match code challenge"() {
        given:
        S256PkceGenerator generator = beanContext.getBean(S256PkceGenerator)

        expect:
        !generator.supportsAny(["plain"])
        generator.supportsAny(["plain", "S256"])
        generator.supportsAny(["S256"])

        when:
        Pkce pkce = generator.generate();

        then:
        pkce.codeChallenge != pkce.codeVerifier
        pkce.codeChallengeMethod == 'S256'
    }
}
