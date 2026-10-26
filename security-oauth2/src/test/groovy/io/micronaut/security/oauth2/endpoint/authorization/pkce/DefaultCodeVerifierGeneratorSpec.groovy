package io.micronaut.security.oauth2.endpoint.authorization.pkce

import io.micronaut.context.BeanContext
import io.micronaut.test.extensions.spock.annotation.MicronautTest
import jakarta.inject.Inject
import spock.lang.Specification

@MicronautTest(startApplication = false)
class DefaultCodeVerifierGeneratorSpec extends Specification {
    @Inject
    BeanContext beanContext

    void "default entropy generates a code verifier within RFC 7636 length bounds"() {
        given:
        CodeVerifierGenerator generator = beanContext.getBean(CodeVerifierGenerator)

        expect:
        generator instanceof DefaultCodeVerifierGenerator

        when:
        String codeVerifier = generator.generate()

        then:
        codeVerifier.length() >= 43
        codeVerifier.length() <= 128
        codeVerifier ==~ /[A-Za-z0-9\-._~]+/
    }

    void "each generated code verifier is different"() {
        given:
        CodeVerifierGenerator generator = beanContext.getBean(CodeVerifierGenerator)

        when:
        String first = generator.generate()
        String second = generator.generate()

        then:
        first != second
    }
}
