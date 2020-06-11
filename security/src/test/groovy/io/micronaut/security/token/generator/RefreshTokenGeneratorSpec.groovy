package io.micronaut.security.token.generator

import edu.umd.cs.findbugs.annotations.NonNull
import io.micronaut.context.annotation.Requires
import io.micronaut.security.ApplicationContextSpecification
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.token.config.TokenConfiguration
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
    void "RefreshTokenGenerator::generate does not validate parameters"(String username, String token, String description) {
        when:
        refreshTokenGenerator.generate(username == null ? null : Authentication.build(username, new TokenConfiguration() {}), token)

        then:
        noExceptionThrown()

        where:
        username | token
        null     | 'xxx'
        'user'   | null
        'user'   | ''
        description = username == null ? 'authentication name can be null' : (token == null ? 'token can be null' : (token == '' ? 'token can be blank': ''))
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
