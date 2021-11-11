package io.micronaut.security.token.jwt.signature.jwks

import com.fasterxml.jackson.databind.ObjectMapper
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.JWKGenerator
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jwt.JWT
import com.nimbusds.jwt.JWTParser
import com.nimbusds.jwt.SignedJWT
import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Replaces
import io.micronaut.context.annotation.Requires
import io.micronaut.core.async.annotation.SingleResult
import io.micronaut.core.util.StringUtils
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
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
import io.micronaut.security.token.generator.TokenGenerator
import io.micronaut.security.token.jwt.encryption.EncryptionConfiguration
import io.micronaut.security.token.jwt.endpoints.JwkProvider
import io.micronaut.security.token.jwt.endpoints.KeysController
import io.micronaut.security.token.jwt.generator.JwtTokenGenerator
import io.micronaut.security.token.jwt.generator.claims.ClaimsGenerator
import io.micronaut.security.token.jwt.render.BearerAccessRefreshToken
import io.micronaut.security.token.jwt.signature.SignatureGeneratorConfiguration
import io.micronaut.security.token.jwt.signature.rsa.RSASignatureGenerator
import io.micronaut.security.token.jwt.signature.rsa.RSASignatureGeneratorConfiguration
import jakarta.inject.Named
import jakarta.inject.Singleton
import org.reactivestreams.Publisher
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification

import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

class JwksCacheSpec extends Specification {

    @Shared
    Map<String, Object> authServerConfig = [
            'micronaut.http.client.read-timeout': '30s',
            'micronaut.security.authentication': 'bearer',
    ]

    @AutoCleanup
    @Shared
    EmbeddedServer googleEmbeddedServer = ApplicationContext.run(EmbeddedServer, authServerConfig + [
            'spec.name': 'GoogleJwksCacheSpec',
            'endpoints.refresh.enabled': StringUtils.TRUE,
            'endpoints.refresh.sensitive': StringUtils.FALSE,
    ])

    @AutoCleanup
    @Shared
    EmbeddedServer cognitoEmbeddedServer = ApplicationContext.run(EmbeddedServer, authServerConfig + [
            'spec.name': 'CognitoJwksCacheSpec',
            'endpoints.refresh.enabled': StringUtils.TRUE,
            'endpoints.refresh.sensitive': StringUtils.FALSE,
    ])

    @AutoCleanup
    @Shared
    EmbeddedServer appleEmbeddedServer = ApplicationContext.run(EmbeddedServer, authServerConfig + [
            'spec.name': 'AppleJwksCacheSpec',
    ])

    @AutoCleanup
    @Shared
    EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer, [
            'micronaut.http.client.read-timeout': '30s',
            'micronaut.security.token.jwt.signatures.jwks.apple.url': "http://localhost:${appleEmbeddedServer.port}/keys",
            'micronaut.security.token.jwt.signatures.jwks.google.url': "http://localhost:${googleEmbeddedServer.port}/keys",
            'micronaut.security.token.jwt.signatures.jwks.cognito.url': "http://localhost:${cognitoEmbeddedServer.port}/keys",
            'spec.name': 'JwksCacheSpec'
    ])

    int googleInvocations() {
        googleEmbeddedServer.applicationContext.getBean(GoogleKeysController).invocations
    }

    int appleInvocations() {
        appleEmbeddedServer.applicationContext.getBean(AppleKeysController).invocations
    }

    int cognitoInvocations() {
        cognitoEmbeddedServer.applicationContext.getBean(CognitoKeysController).invocations
    }

    static String login(BlockingHttpClient client) {
        BearerAccessRefreshToken bearerAccessRefreshToken = client.retrieve(HttpRequest.POST('/login', [username: 'sherlock', password: 'elementary']), BearerAccessRefreshToken)
        assert bearerAccessRefreshToken
        assert bearerAccessRefreshToken.accessToken
        bearerAccessRefreshToken.accessToken
    }

    static void refresh(BlockingHttpClient client) {
        HttpResponse<?> response = client.exchange(HttpRequest.POST('/refresh', '{"force": true}'))
        assert response.status() == HttpStatus.OK
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
        0 == googleInvocations()
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
        0 == googleInvocations()
        0 == appleInvocations()
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
        0 == googleInvocations()
        0 == appleInvocations()
        0 == cognitoInvocations()
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
        1 == googleInvocations()
        1 >= appleInvocations()
        1 >= cognitoInvocations()

        when:
        response = client.retrieve(HttpRequest.GET('/hello').bearerAuth(appleAccessToken))

        then:
        'Hello World' == response
        1 == googleInvocations()
        1 == appleInvocations()
        1 >= cognitoInvocations()

        when:
        response = client.retrieve(HttpRequest.GET('/hello').bearerAuth(cognitoAccessToken))

        then:
        'Hello World' == response
        1 == googleInvocations()
        1 == appleInvocations()
        1 == cognitoInvocations()

        when: 'when you invoke it again all the keys are cached'
        response = client.retrieve(HttpRequest.GET('/hello').bearerAuth(appleAccessToken))

        then:
        'Hello World' == response
        1 == googleInvocations()
        1 == appleInvocations()
        1 == cognitoInvocations()

        when: "generate new keys for cognito, other JWK sets do not match the ID, for cognito the verification key fails and a new one is fetched from the server"
        int invocations = cognitoInvocations()
        refresh(cognitoClient)
        cognitoEmbeddedServer.applicationContext.getBean(CognitoKeysController).invocations = invocations
        cognitoAccessToken = login(cognitoClient)
        response = client.retrieve(HttpRequest.GET('/hello').bearerAuth(cognitoAccessToken))

        then:
        'Hello World' == response
        1 == googleInvocations()
        1 == appleInvocations()
        2 == cognitoInvocations()

        when:
        CognitoSignatureConfiguration cognitoSignatureConfiguration = cognitoEmbeddedServer.applicationContext.getBean(CognitoSignatureConfiguration)
        invocations = cognitoInvocations()
        refresh(cognitoClient)
        cognitoEmbeddedServer.applicationContext.getBean(CognitoKeysController).invocations = invocations
        cognitoSignatureConfiguration.rotateKid()
        cognitoAccessToken = login(cognitoClient)
        response = client.retrieve(HttpRequest.GET('/hello').bearerAuth(cognitoAccessToken))

        then:
        'Hello World' == response
        2 >= googleInvocations()
        2 >= appleInvocations()
        3 == cognitoInvocations()

        when:
        GoogleSignatureConfiguration googleSignatureConfiguration = googleEmbeddedServer.applicationContext.getBean(GoogleSignatureConfiguration)
        invocations = googleInvocations()
        refresh(googleClient)
        googleEmbeddedServer.applicationContext.getBean(GoogleKeysController).invocations = invocations
        googleSignatureConfiguration.clearKid()
        googleAccessToken = login(googleClient)
        response = client.retrieve(HttpRequest.GET('/hello').bearerAuth(googleAccessToken))

        then:
        'Hello World' == response
        3 == googleInvocations()
        2 >= appleInvocations()
        3 == cognitoInvocations()
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

    @Requires(property = 'spec.name', value = 'GoogleJwksCacheSpec')
    @Controller("/keys")
    @Replaces(KeysController.class)
    static class GoogleKeysController extends KeysController {
        int invocations = 0
        GoogleKeysController(Collection<JwkProvider> jwkProviders, ObjectMapper objectMapper) {
            super(jwkProviders, objectMapper)
        }
        @Get
        @SingleResult
        Publisher<String> keys() {
            Publisher<String> result = super.keys()
            invocations++
            return result
        }
    }

    @Requires(property = 'spec.name', value = 'AppleJwksCacheSpec')
    @Controller("/keys")
    @Replaces(KeysController.class)
    static class AppleKeysController extends KeysController {
        int invocations = 0
        AppleKeysController(Collection<JwkProvider> jwkProviders, ObjectMapper objectMapper) {
            super(jwkProviders, objectMapper)
        }
        @Get
        @SingleResult
        Publisher<String> keys() {
            Publisher<String> result = super.keys()
            invocations++
            return result
        }
    }

    @Requires(property = 'spec.name', value = 'CognitoJwksCacheSpec')
    @Controller("/keys")
    @Replaces(KeysController.class)
    static class CognitoKeysController extends KeysController {
        int invocations = 0
        CognitoKeysController(Collection<JwkProvider> jwkProviders, ObjectMapper objectMapper) {
            super(jwkProviders, objectMapper)
        }
        @Get
        @SingleResult
        Publisher<String> keys() {
            Publisher<String> result = super.keys()
            invocations++
            return result
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
    @Named("generator")
    @Singleton
    static class AppleSignatureConfiguration implements RSASignatureGeneratorConfiguration, JwkProvider {
        private List<JWK> jwks
        private final static String KID = 'apple'
        private RSAKey rsaKey
        private final static JWSAlgorithm ALG = JWSAlgorithm.RS256
        AppleSignatureConfiguration() {
            refreshKey()
        }

        void refreshKey() {
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
            jwks
        }
    }

    @Requires(property = 'spec.name', value = 'CognitoJwksCacheSpec')
    @Refreshable
    @Singleton
    @Replaces(JwtTokenGenerator.class)
    static class JwtTokenGeneratorReplacement extends JwtTokenGenerator {
        JwtTokenGeneratorReplacement(CognitoSignatureConfiguration cognitoSignatureConfiguration,
                                     ClaimsGenerator claimsGenerator) {
            super(new RSASignatureGenerator(cognitoSignatureConfiguration), null, claimsGenerator)
        }
    }

    @Requires(property = 'spec.name', value = 'CognitoJwksCacheSpec')
    @Named("generator")
    @Refreshable
    @Singleton
    static class CognitoSignatureConfiguration implements RSASignatureGeneratorConfiguration, JwkProvider {

        private final static JWSAlgorithm ALG = JWSAlgorithm.RS256
        private List<JWK> jwks
        private RSAKey rsaKey
        String kid = 'cognito'

        CognitoSignatureConfiguration() {
            this.rsaKey = null
            this.jwks = null
        }

        void rotateKid() {
            this.kid = 'cognito-' + UUID.randomUUID().toString().substring(0, 5)
        }

        void clearKid() {
            this.kid = null
        }

        List<JWK> getJwks() {
            if (jwks == null) {
                this.jwks = Collections.singletonList(rsaKey.toPublicJWK())
            }
            return jwks
        }

        RSAKey getRsaKey() {
            if (rsaKey == null) {
                JWKGenerator jwkGenerator = new RSAKeyGenerator(2048)
                        .algorithm(ALG)
                        .keyUse(KeyUse.SIGNATURE)
                if (kid) {
                    jwkGenerator = jwkGenerator.keyID(kid)
                }
                this.rsaKey = jwkGenerator.generate()
            }
            return rsaKey
        }

        @Override
        RSAPublicKey getPublicKey() {
            getRsaKey().toRSAPublicKey()
        }

        @Override
        RSAPrivateKey getPrivateKey() {
            getRsaKey().toRSAPrivateKey()
        }

        @Override
        JWSAlgorithm getJwsAlgorithm() {
            ALG
        }

        @Override
        List<JWK> retrieveJsonWebKeys() {
            getJwks()
        }
    }

    @Requires(property = 'spec.name', value = 'GoogleJwksCacheSpec')
    @Refreshable
    @Singleton
    @Replaces(JwtTokenGenerator.class)
    static class GoogleJwtTokenGeneratorReplacement extends JwtTokenGenerator {
        GoogleJwtTokenGeneratorReplacement(GoogleSignatureConfiguration googleSignatureConfiguration,
                                           ClaimsGenerator claimsGenerator) {
            super(new RSASignatureGenerator(googleSignatureConfiguration), null, claimsGenerator)
        }
    }

    @Requires(property = 'spec.name', value = 'GoogleJwksCacheSpec')
    @Named("generator")
    @Refreshable
    @Singleton
    static class GoogleSignatureConfiguration implements RSASignatureGeneratorConfiguration, JwkProvider {
        private final static JWSAlgorithm ALG = JWSAlgorithm.RS256
        private List<JWK> jwks
        private RSAKey rsaKey
        String kid = 'google'

        GoogleSignatureConfiguration() {
            this.rsaKey = null
            this.jwks = null
        }

        void rotateKid() {
            this.kid = 'google-' + UUID.randomUUID().toString().substring(0, 5)
        }

        void clearKid() {
            this.kid = null
        }

        List<JWK> getJwks() {
            if (jwks == null) {
                this.jwks = Collections.singletonList(rsaKey.toPublicJWK())
            }
            return jwks
        }

        RSAKey getRsaKey() {
            if (rsaKey == null) {
                JWKGenerator jwkGenerator = new RSAKeyGenerator(2048)
                        .algorithm(ALG)
                        .keyUse(KeyUse.SIGNATURE)
                if (kid) {
                    jwkGenerator = jwkGenerator.keyID(kid)
                }
                this.rsaKey = jwkGenerator.generate()
            }
            return rsaKey
        }

        @Override
        RSAPublicKey getPublicKey() {
            getRsaKey().toRSAPublicKey()
        }

        @Override
        RSAPrivateKey getPrivateKey() {
            getRsaKey().toRSAPrivateKey()
        }

        @Override
        JWSAlgorithm getJwsAlgorithm() {
            ALG
        }

        @Override
        List<JWK> retrieveJsonWebKeys() {
            getJwks()
        }
    }
}
