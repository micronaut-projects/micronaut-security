package io.micronaut.security.token.jwt.signature.jwks

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jwt.JWT
import com.nimbusds.jwt.JWTParser
import com.nimbusds.jwt.SignedJWT
import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Produces
import io.micronaut.http.client.BlockingHttpClient
import io.micronaut.http.client.HttpClient
import io.micronaut.runtime.context.scope.Refreshable
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.annotation.Secured
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.testutils.authprovider.MockAuthenticationProvider
import io.micronaut.security.testutils.authprovider.SuccessAuthenticationScenario
import io.micronaut.security.token.jwt.endpoints.JwkProvider
import io.micronaut.security.token.jwt.render.BearerAccessRefreshToken
import io.micronaut.security.token.jwt.signature.rsa.RSASignatureConfiguration
import io.micronaut.security.token.jwt.signature.rsa.RSASignatureGeneratorConfiguration
import jakarta.inject.Named
import jakarta.inject.Singleton
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification

import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

class JwksCacheSpec extends Specification {

    @AutoCleanup
    @Shared
    EmbeddedServer googleEmbeddedServer = ApplicationContext.run(EmbeddedServer, [
            'micronaut.security.authentication'   : 'bearer',
            'spec.name': 'GoogleJwksCacheSpec'
    ])

    @AutoCleanup
    @Shared
    EmbeddedServer cognitoEmbeddedServer = ApplicationContext.run(EmbeddedServer, [
            'micronaut.security.authentication'   : 'bearer',
            'spec.name': 'CognitoJwksCacheSpec'
    ])

    @AutoCleanup
    @Shared
    EmbeddedServer appleEmbeddedServer = ApplicationContext.run(EmbeddedServer, [
            'micronaut.security.authentication'   : 'bearer',
            'spec.name': 'AppleJwksCacheSpec'
    ])

    @AutoCleanup
    @Shared
    EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer, [
            'micronaut.security.token.jwt.signatures.jwks.apple.url': "http://localhost:${appleEmbeddedServer.port}/keys",
            'micronaut.security.token.jwt.signatures.jwks.google.url': "http://localhost:${googleEmbeddedServer.port}/keys",
            'micronaut.security.token.jwt.signatures.jwks.cognito.url': "http://localhost:${cognitoEmbeddedServer.port}/keys",
            'spec.name': 'JwksCacheSpec'
    ])

    int googleInvocations() {
        GoogleSignatureConfiguration googleJsonWebKeysProvider = googleEmbeddedServer.applicationContext.getBean(GoogleSignatureConfiguration)
        googleJsonWebKeysProvider.invocations
    }

    int appleInvocations() {
        AppleSignatureConfiguration appleJsonWebKeysProvider = appleEmbeddedServer.applicationContext.getBean(AppleSignatureConfiguration)
        appleJsonWebKeysProvider.invocations
    }

    int cognitoInvocations() {
        CognitoSignatureConfiguration cognitoJsonWebKeysProvider = cognitoEmbeddedServer.applicationContext.getBean(CognitoSignatureConfiguration)
        cognitoJsonWebKeysProvider.invocations
    }


    void "JWK are cached"() {
        expect:
        0 == googleInvocations()
        0 == appleInvocations()
        0 == cognitoInvocations()

        when:
        HttpClient googleHttpClient = embeddedServer.applicationContext.createBean(HttpClient, googleEmbeddedServer.URL)
        BlockingHttpClient googleClient = googleHttpClient.toBlocking()
        BearerAccessRefreshToken googleBearerAccessRefreshToken = googleClient.retrieve(HttpRequest.POST('/login', [username: 'sherlock', password: 'elementary']), BearerAccessRefreshToken)

        then:
        noExceptionThrown()
        1 == googleInvocations()
        0 == appleInvocations()
        0 == cognitoInvocations()
        googleBearerAccessRefreshToken.accessToken

        when:
        String googleAccessToken = googleBearerAccessRefreshToken.accessToken
        JWT googleJWT = JWTParser.parse(googleAccessToken)

        then:
        googleJWT instanceof SignedJWT
        ((SignedJWT) googleJWT).getHeader().getKeyID() == 'google'

        when:
        HttpClient appleHttpClient = embeddedServer.applicationContext.createBean(HttpClient, appleEmbeddedServer.URL)
        BlockingHttpClient appleClient = appleHttpClient.toBlocking()
        BearerAccessRefreshToken appleBearerAccessRefreshToken = appleClient.retrieve(HttpRequest.POST('/login', [username: 'sherlock', password: 'elementary']), BearerAccessRefreshToken)

        then:
        noExceptionThrown()
        1 == googleInvocations()
        1 == appleInvocations()
        0 == cognitoInvocations()
        appleBearerAccessRefreshToken.accessToken

        when:
        String appleAccessToken = appleBearerAccessRefreshToken.accessToken
        JWT appleJWT = JWTParser.parse(appleAccessToken)

        then:
        appleJWT instanceof SignedJWT
        ((SignedJWT) appleJWT).getHeader().getKeyID() == 'apple'

        when:
        HttpClient cognitoHttpClient = embeddedServer.applicationContext.createBean(HttpClient, cognitoEmbeddedServer.URL)
        BlockingHttpClient cognitoClient = cognitoHttpClient.toBlocking()
        BearerAccessRefreshToken cognitoBearerAccessRefreshToken = cognitoClient.retrieve(HttpRequest.POST('/login', [username: 'sherlock', password: 'elementary']), BearerAccessRefreshToken)

        then:
        noExceptionThrown()
        1 == googleInvocations()
        1 == appleInvocations()
        1 == cognitoInvocations()
        cognitoBearerAccessRefreshToken.accessToken

        when:
        String cognitoAccessToken = cognitoBearerAccessRefreshToken.accessToken
        JWT cognitoJWT = JWTParser.parse(cognitoAccessToken)

        then:
        cognitoJWT instanceof SignedJWT
        ((SignedJWT) cognitoJWT).getHeader().getKeyID() == 'cognito'

        when:
        HttpClient httpClient = embeddedServer.applicationContext.createBean(HttpClient, embeddedServer.URL)
        BlockingHttpClient client = httpClient.toBlocking()
        String response = client.retrieve(HttpRequest.GET('/hello').bearerAuth(googleAccessToken))

        then:
        'Hello World' == response
        2 == googleInvocations()
        2 == appleInvocations()
        2 == cognitoInvocations()

        when:
        response = client.retrieve(HttpRequest.GET('/hello').bearerAuth(appleAccessToken))

        then:
        'Hello World' == response
        2 == googleInvocations()
        2 == appleInvocations()
        2 == cognitoInvocations()

        when:
        response = client.retrieve(HttpRequest.GET('/hello').bearerAuth(cognitoAccessToken))

        then:
        'Hello World' == response
        2 == googleInvocations()
        2 == appleInvocations()
        2 == cognitoInvocations()
    }

    @Requires(property = 'spec.name', value = 'JwksCacheSpec')
    @Controller("/hello")
    static class HelloWorldController {
        @Produces(MediaType.TEXT_PLAIN)
        @Get
        @Secured(SecurityRule.IS_AUTHENTICATED)
        String index() {
            'Hello World'
        }
    }

    @Singleton
    @Requires(property = 'spec.name', value = 'AppleJwksCacheSpec')
    static class AppleAuthenticationProvider extends MockAuthenticationProvider {
        AppleAuthenticationProvider() {
            super([new SuccessAuthenticationScenario('sherlock', [])])
        }
    }

    @Singleton
    @Requires(property = 'spec.name', value = 'CognitoJwksCacheSpec')
    static class CognitoAuthenticationProvider extends MockAuthenticationProvider {
        CognitoAuthenticationProvider() {
            super([new SuccessAuthenticationScenario('sherlock', [])])
        }
    }

    @Singleton
    @Requires(property = 'spec.name', value = 'GoogleJwksCacheSpec')
    static class GoogleAuthenticationProvider extends MockAuthenticationProvider {
        GoogleAuthenticationProvider() {
            super([new SuccessAuthenticationScenario('sherlock', [])])
        }
    }

    @Requires(property = 'spec.name', value = 'AppleJwksCacheSpec')
    @Refreshable
    @Named("generator")
    static class AppleSignatureConfiguration implements RSASignatureGeneratorConfiguration, JwkProvider {
        private final List<JWK> jwks
        int invocations = 0
        private final static String KID = 'apple'
        private final RSAKey rsaKey
        private final static JWSAlgorithm ALG = JWSAlgorithm.RS256
        AppleSignatureConfiguration() {
            this.rsaKey = new RSAKeyGenerator(2048)
                    .algorithm(ALG)
                    .keyUse(KeyUse.SIGNATURE)
                    .keyID(KID)
                    .generate()

            this.jwks = Collections.singletonList(rsaKey.toPublicJWK())
        }

        @Override
        RSAPublicKey getPublicKey() {
            rsaKey.toRSAPublicKey()
        }

        @Override
        RSAPrivateKey getPrivateKey() {
            rsaKey.toRSAPrivateKey()
        }

        @Override
        JWSAlgorithm getJwsAlgorithm() {
            ALG
        }

        @Override
        List<JWK> retrieveJsonWebKeys() {
            invocations++
            jwks
        }
    }

    @Requires(property = 'spec.name', value = 'CognitoJwksCacheSpec')
    @Refreshable
    @Named("generator")
    static class CognitoSignatureConfiguration implements RSASignatureGeneratorConfiguration, JwkProvider {
        private final List<JWK> jwks
        int invocations = 0
        private final static String KID = 'cognito'
        private final RSAKey rsaKey
        private final static JWSAlgorithm ALG = JWSAlgorithm.RS256
        CognitoSignatureConfiguration() {
            this.rsaKey = new RSAKeyGenerator(2048)
                    .algorithm(ALG)
                    .keyUse(KeyUse.SIGNATURE)
                    .keyID(KID)
                    .generate()
            this.jwks = Collections.singletonList(rsaKey.toPublicJWK())
        }

        @Override
        RSAPublicKey getPublicKey() {
            rsaKey.toRSAPublicKey()
        }

        @Override
        RSAPrivateKey getPrivateKey() {
            rsaKey.toRSAPrivateKey()
        }

        @Override
        JWSAlgorithm getJwsAlgorithm() {
            ALG
        }

        @Override
        List<JWK> retrieveJsonWebKeys() {
            invocations++
            jwks
        }
    }

    @Requires(property = 'spec.name', value = 'GoogleJwksCacheSpec')
    @Refreshable
    @Named("generator")
    static class GoogleSignatureConfiguration implements RSASignatureGeneratorConfiguration, JwkProvider {
        int invocations = 0
        private final List<JWK> jwks
        private final static String KID = 'google'
        private final static JWSAlgorithm ALG = JWSAlgorithm.RS256
        private final RSAKey rsaKey
        GoogleSignatureConfiguration() {
            this.rsaKey = new RSAKeyGenerator(2048)
                    .algorithm(ALG)
                    .keyUse(KeyUse.SIGNATURE)
                    .keyID(KID)
                    .generate()
            this.jwks = Collections.singletonList(rsaKey.toPublicJWK())
        }

        @Override
        RSAPublicKey getPublicKey() {
            rsaKey.toRSAPublicKey()
        }

        @Override
        RSAPrivateKey getPrivateKey() {
            rsaKey.toRSAPrivateKey()
        }

        @Override
        JWSAlgorithm getJwsAlgorithm() {
            ALG
        }

        @Override
        List<JWK> retrieveJsonWebKeys() {
            invocations++
            jwks
        }
    }
}
