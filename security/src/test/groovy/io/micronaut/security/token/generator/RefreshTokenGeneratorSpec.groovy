package io.micronaut.security.token.generator

import io.micronaut.core.annotation.NonNull
import io.micronaut.context.annotation.Requires
import io.micronaut.security.testutils.ApplicationContextSpecification
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.token.config.TokenConfiguration
import spock.lang.Shared
import spock.lang.Subject
import spock.lang.Unroll

import jakarta.inject.Singleton

class RefreshTokenGeneratorSpec extends ApplicationContextSpecification {

    @Override
    String getSpecName() {
        'RefreshTokenGeneratorSpec'
    }

    @Subject
    @Shared
    RefreshTokenGenerator refreshTokenGenerator = applicationContext.getBean(RefreshTokenGenerator)

    @Shared
    TokenConfiguration tokenConfiguration = applicationContext.getBean(TokenConfiguration)

    void "for RefreshTokenGenerator::createKey user details can be null"() {
        when:
        refreshTokenGenerator.createKey(null)

        then:
        noExceptionThrown()
    }

    @Unroll("For RefreshTokenGenerator::generate #description")
    void "RefreshTokenGenerator::generate does not validate parameters"(Authentication authentication, String token, String description) {
        when:
        refreshTokenGenerator.generate(authentication, token)

        then:
        noExceptionThrown()

        where:
        authentication               | token
        null                         | 'xxx'
        Authentication.build('user') | null
        Authentication.build('user') | ''
        description = authentication == null ? 'authentication can be null' : (token == null ? 'token can be null' : (token == '' ? 'token can be blank': ''))
    }

    @Requires(property = 'spec.name', value = 'RefreshTokenGeneratorSpec')
    @Singleton
    static class CustomRefreshTokenGenerator implements RefreshTokenGenerator {
        @Override
        String createKey(@NonNull Authentication authentication) {
            return 'foo'
        }

        @Override
        Optional<String> generate(@NonNull Authentication authentication, @NonNull String token) {
            return Optional.of('faa')
        }
    }
}
