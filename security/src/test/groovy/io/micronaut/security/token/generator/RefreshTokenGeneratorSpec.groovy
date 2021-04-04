package io.micronaut.security.token.generator

import io.micronaut.core.annotation.NonNull
import io.micronaut.context.annotation.Requires
import io.micronaut.security.ApplicationContextSpecification
import io.micronaut.security.authentication.UserDetails
import spock.lang.Shared
import spock.lang.Subject
import spock.lang.Unroll

import javax.inject.Singleton

class RefreshTokenGeneratorSpec extends ApplicationContextSpecification {

    @Override
    String getSpecName() {
        'RefreshTokenGeneratorSpec'
    }

    @Subject
    @Shared
    RefreshTokenGenerator refreshTokenGenerator = applicationContext.getBean(RefreshTokenGenerator)

    void "for RefreshTokenGenerator::createKey user details can be null"() {
        when:
        refreshTokenGenerator.createKey(null)

        then:
        noExceptionThrown()
    }

    @Unroll("For RefreshTokenGenerator::generate #description")
    void "RefreshTokenGenerator::generate does not validate parameters"(UserDetails userDetails, String token, String description) {
        when:
        refreshTokenGenerator.generate(userDetails, token)

        then:
        noExceptionThrown()

        where:
        userDetails                 | token
        null                        | 'xxx'
        new UserDetails("user", []) | null
        new UserDetails("user", []) | ''
        description = userDetails == null ? 'userDetails can be null' : (token == null ? 'token can be null' : (token == '' ? 'token can be blank': ''))
    }

    @Requires(property = 'spec.name', value = 'RefreshTokenGeneratorSpec')
    @Singleton
    static class CustomRefreshTokenGenerator implements RefreshTokenGenerator {
        @Override
        String createKey(@NonNull UserDetails userDetails) {
            return 'foo'
        }

        @Override
        Optional<String> generate(@NonNull UserDetails userDetails, @NonNull String token) {
            return Optional.of('faa')
        }
    }
}
