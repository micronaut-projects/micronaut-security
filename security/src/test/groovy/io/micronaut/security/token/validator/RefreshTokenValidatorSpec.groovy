package io.micronaut.security.token.validator

import io.micronaut.core.annotation.NonNull
import io.micronaut.context.annotation.Requires
import io.micronaut.security.testutils.ApplicationContextSpecification
import spock.lang.Shared
import spock.lang.Subject
import spock.lang.Unroll

import javax.inject.Singleton

class RefreshTokenValidatorSpec extends ApplicationContextSpecification {

    @Override
    String getSpecName() {
        'RefreshTokenValidatorSpec'
    }

    @Subject
    @Shared
    RefreshTokenValidator refreshTokenValidator = applicationContext.getBean(RefreshTokenValidator)

    @Unroll("For RefreshTokenValidator::validate #token does not throw ConstraintViolationException")
    void "RefreshTokenValidator::validate does not validate parameter"(String token) {
        when:
        refreshTokenValidator.validate(token)

        then:
        noExceptionThrown()

        where:
        token << [null, '']
    }

    @Requires(property = 'spec.name', value = 'RefreshTokenValidatorSpec')
    @Singleton
    static class CustomRefreshTokenValidator implements RefreshTokenValidator {

        @Override
        @NonNull
        Optional<String> validate(@NonNull String refreshToken) {
            return Optional.ofNullable(refreshToken)
        }
    }
}
