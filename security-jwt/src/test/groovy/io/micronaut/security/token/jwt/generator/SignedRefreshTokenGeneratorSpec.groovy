package io.micronaut.security.token.jwt.generator

import com.nimbusds.jose.JWSObject
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.token.config.TokenConfiguration
import io.micronaut.testutils.ApplicationContextSpecification
import spock.lang.Shared
import spock.lang.Subject

class SignedRefreshTokenGeneratorSpec extends ApplicationContextSpecification {
    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.token.jwt.generator.refresh-token.secret': 'pleaseChangeThisSecretForANewOne',
        ] as Map<String, Object>
    }

    @Subject
    @Shared
    SignedRefreshTokenGenerator jwsRefreshTokenGenerator = applicationContext.getBean(SignedRefreshTokenGenerator)

    void "get payload, signit and verify it"() {
        given:
        Authentication user = Authentication.build("sherlock", new TokenConfiguration() {})

        when: 'can generate a payload'
        String payload = jwsRefreshTokenGenerator.createKey(user)

        then:
        payload

        when:
        Optional<String> signedPayloadOptional = jwsRefreshTokenGenerator.generate(user, payload)

        then:
        signedPayloadOptional.isPresent()

        when:
        String signedPayload = signedPayloadOptional.get()

        then: 'signed payload is not same as payload'
        payload != signedPayload

        when:
        JWSObject.parse(signedPayload)

        then: 'signed payload is a JWS object'
        noExceptionThrown()

        when:
        Optional<String> validated = jwsRefreshTokenGenerator.validate(signedPayload)

        then:
        validated.isPresent()
        validated.get() == payload

        when:
        validated = jwsRefreshTokenGenerator.validate('bogus')

        then:
        !validated.isPresent()
    }
}
