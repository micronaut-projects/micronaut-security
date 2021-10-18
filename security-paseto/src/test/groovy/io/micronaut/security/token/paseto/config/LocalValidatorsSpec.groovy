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

    private static String generateSharedSecret() {
        new String(Keys.secretKey().getEncoded(), StandardCharsets.UTF_8)
    }
}
