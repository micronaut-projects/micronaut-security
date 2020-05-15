package io.micronaut.security.token.validator

import edu.umd.cs.findbugs.annotations.NonNull
import io.micronaut.context.annotation.Requires
import io.micronaut.security.ApplicationContextSpecification
import spock.lang.Shared
import spock.lang.Subject
import spock.lang.Unroll

import javax.inject.Singleton
import javax.validation.ConstraintViolationException
import javax.validation.constraints.NotBlank

class RefreshTokenValidatorSpec extends ApplicationContextSpecification {

    @Override
    String getSpecName() {
        'RefreshTokenValidatorSpec'
    }

    @Subject
    @Shared
    RefreshTokenValidator refreshTokenValidator = applicationContext.getBean(RefreshTokenValidator)

    @Unroll("For RefreshTokenValidator::validate #token throws ConstraintViolationException")
    void "RefreshTokenValidator::validate constraints"(String token) {
        when:
        refreshTokenValidator.validate(token)

        then:
        thrown(ConstraintViolationException)

        where:
        token << [null, '']
    }

    @Requires(property = 'spec.name', value = 'RefreshTokenValidatorSpec')
    @Singleton
    static class CustomRefreshTokenValidator implements RefreshTokenValidator {

        @Override
        @NonNull
        Optional<String> validate(@NonNull @NotBlank String refreshToken) {
            return Optional.ofNullable(refreshToken)
        }
    }
}
