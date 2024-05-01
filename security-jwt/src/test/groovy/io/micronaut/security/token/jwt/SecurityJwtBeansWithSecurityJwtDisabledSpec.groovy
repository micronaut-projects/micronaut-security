package io.micronaut.security.token.jwt

import io.micronaut.context.ApplicationContext
import io.micronaut.context.exceptions.NoSuchBeanException
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.endpoints.OauthController
import io.micronaut.security.endpoints.OauthControllerConfigurationProperties
import io.micronaut.security.token.bearer.AccessRefreshTokenLoginHandler
import io.micronaut.security.token.bearer.BearerTokenConfigurationProperties
import io.micronaut.security.token.bearer.BearerTokenReader
import io.micronaut.security.token.cookie.TokenCookieClearerLogoutHandler
import io.micronaut.security.token.cookie.TokenCookieLoginHandler
import io.micronaut.security.token.generator.AccessRefreshTokenGenerator
import io.micronaut.security.token.generator.AccessTokenConfigurationProperties
import io.micronaut.security.token.jwt.config.JwtConfigurationProperties
import io.micronaut.security.token.jwt.converters.EncryptionMethodConverter
import io.micronaut.security.token.jwt.converters.JWEAlgorithmConverter
import io.micronaut.security.token.jwt.converters.JWSAlgorithmConverter
import io.micronaut.security.token.jwt.encryption.ec.ECEncryptionFactory
import io.micronaut.security.token.jwt.encryption.rsa.RSAEncryptionFactory
import io.micronaut.security.token.jwt.encryption.secret.SecretEncryptionConfiguration
import io.micronaut.security.token.jwt.encryption.secret.SecretEncryptionFactory
import io.micronaut.security.token.jwt.generator.JwtTokenGenerator
import io.micronaut.security.token.jwt.generator.claims.JWTClaimsSetGenerator
import io.micronaut.security.token.jwt.signature.ec.ECSignatureFactory
import io.micronaut.security.token.jwt.signature.ec.ECSignatureGeneratorFactory
import io.micronaut.security.token.jwt.signature.rsa.RSASignatureFactory
import io.micronaut.security.token.jwt.signature.rsa.RSASignatureGeneratorFactory

import io.micronaut.security.token.render.BearerTokenRenderer
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification
import spock.lang.Unroll

class SecurityJwtBeansWithSecurityJwtDisabledSpec extends Specification {

    @Shared
    @AutoCleanup
    EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer, [
            'spec.name'                 : SecurityJwtBeansWithSecurityJwtDisabledSpec.simpleName,
            'micronaut.security.token.jwt.enabled': false,
    ])

    @Unroll("if micronaut.security.enabled=true and micronaut.security.token.jwt.enabled=false bean [#description] is not loaded")
    void "if micronaut.security.token.jwt.enabled=false security related beans are not loaded"(Class clazz, String description) {
        when:
        embeddedServer.applicationContext.getBean(clazz)

        then:
        NoSuchBeanException e = thrown()
        e.message.contains('No bean of type ['+clazz.name+'] exists.')

        where:
        clazz << [
                AccessRefreshTokenLoginHandler,
                JwtConfigurationProperties,
                EncryptionMethodConverter,
                JWEAlgorithmConverter,
                JWSAlgorithmConverter,
                TokenCookieClearerLogoutHandler,
                TokenCookieLoginHandler,
                ECEncryptionFactory,
                RSAEncryptionFactory,
                SecretEncryptionConfiguration,
                SecretEncryptionFactory,
                OauthController,
                JWTClaimsSetGenerator,
                JwtTokenGenerator,
                ECSignatureFactory,
                ECSignatureGeneratorFactory,
                RSASignatureFactory,
                RSASignatureGeneratorFactory,
                JwtTokenValidator,
        ]

        description = clazz.name
    }
}
