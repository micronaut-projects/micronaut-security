package io.micronaut.security.token.generator

import edu.umd.cs.findbugs.annotations.NonNull
import io.micronaut.context.annotation.Requires
import io.micronaut.security.ApplicationContextSpecification
import io.micronaut.security.authentication.UserDetails
import spock.lang.Shared
import spock.lang.Subject
import spock.lang.Unroll

import javax.inject.Singleton
import javax.validation.ConstraintViolationException
import javax.validation.constraints.NotBlank
import javax.validation.constraints.NotNull

class RefreshTokenGeneratorSpec extends ApplicationContextSpecification {

    @Override
    String getSpecName() {
        'RefreshTokenGeneratorSpec'
    }

    @Subject
    @Shared
    RefreshTokenGenerator refreshTokenGenerator = applicationContext.getBean(RefreshTokenGenerator)

    void "for RefreshTokenGenerator::createKey user details cannot be null"() {
        when:
        refreshTokenGenerator.createKey(null)

        then:
        thrown(ConstraintViolationException)
    }

    @Unroll("For RefreshTokenGenerator::generate #description")
    void "RefreshTokenGenerator::generate constraints"(UserDetails userDetails, String token, String description) {
        when:
        refreshTokenGenerator.generate(userDetails, token)

        then:
        thrown(ConstraintViolationException)

        where:
        userDetails                 | token
        null                        | 'xxx'
        new UserDetails("user", []) | null
        new UserDetails("user", []) | ''
        description = userDetails == null ? 'userDetails cannot be null' : (token == null ? 'token cannot be null' : (token == '' ? 'token cannot be blank': ''))
    }

    @Requires(property = 'spec.name', value = 'RefreshTokenGeneratorSpec')
    @Singleton
    static class CustomRefreshTokenGenerator implements RefreshTokenGenerator {
        @Override
        String createKey(@NonNull @NotNull UserDetails userDetails) {
            return 'foo'
        }

        @Override
        Optional<String> generate(@NonNull @NotNull UserDetails userDetails, @NonNull @NotBlank String token) {
            return 'faa'
        }
    }
}
