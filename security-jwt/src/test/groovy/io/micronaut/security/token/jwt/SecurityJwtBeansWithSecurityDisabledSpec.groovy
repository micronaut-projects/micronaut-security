package io.micronaut.security.token.jwt

import io.micronaut.context.ApplicationContext
import io.micronaut.context.env.Environment
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
import io.micronaut.security.token.jwt.validator.JwtTokenValidator
import io.micronaut.security.token.render.BearerTokenRenderer
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification
import spock.lang.Unroll

class SecurityJwtBeansWithSecurityDisabledSpec extends Specification {

    @Shared
    @AutoCleanup
    EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer, [
            'spec.name'                 : SecurityJwtBeansWithSecurityDisabledSpec.simpleName,
            'micronaut.security.enabled': false,
    ], Environment.TEST)

    @Unroll("if micronaut.security.enabled=false bean [#description] is not loaded")
    void "if micronaut.security.enabled=false security related beans are not loaded"(Class clazz, String description) {
        when:
        embeddedServer.applicationContext.getBean(clazz)

        then:
        def e = thrown(NoSuchBeanException)
        e.message.contains('No bean of type ['+clazz.name+'] exists.')

        where:
        clazz << [
                AccessRefreshTokenLoginHandler,
                BearerTokenConfigurationProperties,
                BearerTokenReader,
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
                OauthControllerConfigurationProperties,
                JWTClaimsSetGenerator,
                AccessRefreshTokenGenerator,
                AccessTokenConfigurationProperties,
                JwtTokenGenerator,
                BearerTokenRenderer,
                ECSignatureFactory,
                ECSignatureGeneratorFactory,
                RSASignatureFactory,
                RSASignatureGeneratorFactory,
                JwtTokenValidator,
        ]

        description = clazz.name
    }
}
