package io.micronaut.security.token.paseto.config

import dev.paseto.jpaseto.lang.Keys
import io.micronaut.security.testutils.ApplicationContextSpecification
import java.nio.charset.StandardCharsets

class LocalValidatorsSpec extends ApplicationContextSpecification {
    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.token.paseto.local-validators.one.shared-secret': generateSharedSecret(),
                'micronaut.security.token.paseto.local-validators.two.shared-secret': generateSharedSecret(),
        ]
    }

    void "you can generate multiple local token validators"() {
        expect:
        !containsBean(VersionedSharedSecretConfiguration)
        containsBean(SharedSecretConfiguration)
        getBeansOfType(SharedSecretConfiguration).size() == 2
    }

    void "local validator exposes shared secret and required claims"() {
        given:
        def sharedSecret = Keys.secretKey()
        def configuration = new LocalValidators()

        when:
        configuration.base64SharedSecret = sharedSecret
        configuration.requiredAudience = 'audience'
        configuration.requiredKeyId = 'kid'
        configuration.requiredIssuer = 'issuer'
        configuration.requiredSubject = 'subject'
        configuration.requiredTokenId = 'token-id'

        then:
        configuration.sharedSecret.is(sharedSecret)
        configuration.requiredAudience == 'audience'
        configuration.requiredKeyId == 'kid'
        configuration.requiredIssuer == 'issuer'
        configuration.requiredSubject == 'subject'
        configuration.requiredTokenId == 'token-id'
    }

    private static String generateSharedSecret() {
        new String(Keys.secretKey().getEncoded(), StandardCharsets.UTF_8)
    }
}
