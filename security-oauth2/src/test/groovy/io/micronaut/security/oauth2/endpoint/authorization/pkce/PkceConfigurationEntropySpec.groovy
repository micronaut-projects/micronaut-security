package io.micronaut.security.oauth2.endpoint.authorization.pkce

import io.micronaut.context.ApplicationContext
import io.micronaut.context.exceptions.BeanInstantiationException
import io.micronaut.core.util.StringUtils
import spock.lang.Specification

class PkceConfigurationEntropySpec extends Specification {

    void "PkceConfiguration entropy #entropy outside RFC 7636 bounds is rejected"(int entropy, String expectedMessage) {
        given:
        ApplicationContext applicationContext = ApplicationContext.run([
                'micronaut.security.oauth2.pkce.enabled': StringUtils.TRUE,
                'micronaut.security.oauth2.pkce.entropy': entropy
        ])

        when:
        applicationContext.getBean(PkceConfiguration)

        then:
        BeanInstantiationException e = thrown()
        e.message.contains(expectedMessage)

        cleanup:
        applicationContext.close()

        where:
        entropy | expectedMessage
        31      | 'must be greater than or equal to 32'
        97      | 'must be less than or equal to 96'
    }

    void "PkceConfiguration entropy #entropy within RFC 7636 bounds generates a #expectedLength character code verifier"(int entropy, int expectedLength) {
        given:
        ApplicationContext applicationContext = ApplicationContext.run([
                'micronaut.security.oauth2.pkce.enabled': StringUtils.TRUE,
                'micronaut.security.oauth2.pkce.entropy': entropy
        ])

        when:
        PkceConfiguration pkceConfiguration = applicationContext.getBean(PkceConfiguration)

        then:
        noExceptionThrown()
        pkceConfiguration.entropy == entropy

        when:
        String codeVerifier = applicationContext.getBean(CodeVerifierGenerator).generate()

        then:
        codeVerifier.length() == expectedLength
        codeVerifier.length() >= 43
        codeVerifier.length() <= 128

        cleanup:
        applicationContext.close()

        where:
        entropy | expectedLength
        32      | 43
        96      | 128
    }
}
