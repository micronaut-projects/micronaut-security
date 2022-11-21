package io.micronaut.security.oauth2.endpoint.authorization.pkce

import io.micronaut.context.BeanContext
import io.micronaut.context.annotation.Property
import io.micronaut.core.util.StringUtils
import io.micronaut.test.extensions.spock.annotation.MicronautTest
import jakarta.inject.Inject
import spock.lang.Specification

@MicronautTest(startApplication = false)
class PlainPkceGeneratorSpec extends Specification {
    @Inject
    BeanContext beanContext

    void "code verifier matches code challenge"() {
        given:
        PlainPkceGenerator generator = beanContext.getBean(PlainPkceGenerator)

        expect:
        generator.supportsAny(["plain"])
        generator.supportsAny(["plain", "S256"])
        !generator.supportsAny(["S256"])
        !generator.supportsAny([])

        when:
        Pkce pkce = generator.generate()

        then:
        pkce.codeChallenge == pkce.codeVerifier
        pkce.codeChallengeMethod == 'plain'


    }
}
