package io.micronaut.security.token.paseto.config

import dev.paseto.jpaseto.Version
import dev.paseto.jpaseto.lang.Keys
import io.micronaut.security.testutils.ApplicationContextSpecification

class VersionedSharedSecretConfigurationPropertiesSpec extends ApplicationContextSpecification {

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.token.paseto.local-generator.base64-shared-secret': generateSharedSecret()
        ]
    }

    void "micronaut.security.token.paseto.shared-key-generator defaults to version v1"() {
        expect:
        containsBean(VersionedSharedSecretConfiguration)
        containsBean(SharedSecretConfiguration)
        containsBean(RequiredConfiguration)
        getBean(VersionedSharedSecretConfiguration).version == Version.V1
    }

    private static String generateSharedSecret() {
        Base64.getEncoder().encodeToString(Keys.secretKey().getEncoded())
    }
}
