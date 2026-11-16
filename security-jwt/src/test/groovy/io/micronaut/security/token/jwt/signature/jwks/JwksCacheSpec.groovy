package io.micronaut.security.token.jwt.signature.jwks

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.Payload
import com.nimbusds.jose.crypto.MACSigner
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.JWKGenerator
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jwt.JWT
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.JWTParser
import com.nimbusds.jwt.SignedJWT
import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Replaces
import io.micronaut.context.annotation.Requires
import io.micronaut.context.exceptions.NoSuchBeanException
import io.micronaut.core.async.annotation.SingleResult
import io.micronaut.http.HttpRequest
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Produces
import io.micronaut.http.client.BlockingHttpClient
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.json.JsonMapper
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.annotation.Secured
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.token.jwt.endpoints.JwkProvider
import io.micronaut.security.token.jwt.endpoints.KeysController
import io.micronaut.security.token.jwt.signature.rsa.RSASignatureGeneratorConfiguration
import jakarta.inject.Named
import jakarta.inject.Singleton
import org.reactivestreams.Publisher
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification

import java.security.SecureRandom
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

class JwksCacheSpec extends Specification {

    @Shared
    Map<String, Object> authServerConfig = [
            'micronaut.http.client.read-timeout': '30s',
    ]

    @AutoCleanup
    @Shared
    EmbeddedServer googleEmbeddedServer = ApplicationContext.run(EmbeddedServer, authServerConfig + [
            'spec.name': 'GoogleJwksCacheSpec',
    ])

    @AutoCleanup
    @Shared
    EmbeddedServer cognitoEmbeddedServer = ApplicationContext.run(EmbeddedServer, authServerConfig + [
            'spec.name': 'CognitoJwksCacheSpec',
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
            'micronaut.security.token.jwt.signatures.jwks.apple.cache-expiration': 5,
            'micronaut.security.token.jwt.signatures.jwks.google.url': "http://localhost:${googleEmbeddedServer.port}/keys",
            'micronaut.security.token.jwt.signatures.jwks.google.cache-expiration': 5,
            'micronaut.security.token.jwt.signatures.jwks.cognito.url': "http://localhost:${cognitoEmbeddedServer.port}/keys",
            'micronaut.security.token.jwt.signatures.jwks.cognito.cache-expiration': 5,
            'spec.name': 'JwksCacheSpec'
    ])

    private void hello(BlockingHttpClient client, String token, boolean doAssertion = true) {
        HttpRequest<?> request = HttpRequest.GET('/hello').bearerAuth(token)
        if (doAssertion) {
            String response = client.retrieve(request)
            assert 'Hello World' == response
        } else {
            try {
                client.retrieve(request)
            } catch(HttpClientResponseException e) {
                assert true // token is not valid for cached JWKS
            }
        }
    }

    void "JWK are cached"() {
        given:

        HttpClient httpClient = embeddedServer.applicationContext.createBean(HttpClient, embeddedServer.URL)
        BlockingHttpClient client = httpClient.toBlocking()
        GoogleSignatureConfiguration googleSignatureConfiguration = googleEmbeddedServer.applicationContext.getBean(GoogleSignatureConfiguration)
        AppleSignatureConfiguration appleSignatureConfiguration = appleEmbeddedServer.applicationContext.getBean(AppleSignatureConfiguration)
        CognitoSignatureConfiguration cognitoSignatureConfiguration = cognitoEmbeddedServer.applicationContext.getBean(CognitoSignatureConfiguration)

        expect:
        0 == totalInvocations()
        when:
        !embeddedServer.getApplicationContext().getBean(CacheableJwkSetFetcher.class)

        then:
        thrown(NoSuchBeanException)

        when:
        embeddedServer.getApplicationContext().getBean(ReactorCacheJwkSetFetcher.class);

        then:
        noExceptionThrown()

        when:
        String googleAccessToken = accessToken(googleSignatureConfiguration)

        then:
        noExceptionThrown()
        googleAccessToken

        when:
        JWT googleJWT = JWTParser.parse(googleAccessToken)
        String appleAccessToken = accessToken(appleSignatureConfiguration)
        JWT appleJWT = JWTParser.parse(appleAccessToken)
        String cognitoAccessToken = accessToken(cognitoSignatureConfiguration)
        JWT cognitoJWT = JWTParser.parse(cognitoAccessToken)

        then:
        noExceptionThrown()
        assertKeyId(googleJWT, 'google')
        assertKeyId(appleJWT, 'apple')
        appleAccessToken
        assertKeyId(cognitoJWT, 'cognito')
        cognitoAccessToken

        and:
        0 == totalInvocations()

        when:
        int oldInvocations = totalInvocations()
        hello(client, googleAccessToken)
        hello(client, appleAccessToken)
        hello(client, cognitoAccessToken)

        then:
        totalInvocations() >= (oldInvocations + 3)

        when: 'when you invoke it again all the keys are cached'
        oldInvocations = totalInvocations()
        hello(client, appleAccessToken)

        then:
        totalInvocations() == oldInvocations

        when: "generate new keys for cognito but with same id, other JWK sets do not match the ID, for cognito the verification key fails and a new one is fetched from the server"
        oldInvocations = totalInvocations()
        cognitoSignatureConfiguration.refreshKey()
        cognitoAccessToken = accessToken(cognitoSignatureConfiguration)
        sleep(6_000) // sleep for six seconds so JWKS cache expires
        hello(client, cognitoAccessToken)

        then:
        totalInvocations() >= (oldInvocations + 1)

        when: 'generate a new JWKS with new kid, JWKS attempt to refresh'
        oldInvocations = totalInvocations()
        cognitoSignatureConfiguration.rotateKid()
        cognitoAccessToken = accessToken(cognitoSignatureConfiguration)
        sleep(6_000) // sleep for six seconds so JWKS cache expires
        hello(client, cognitoAccessToken)

        then:
        totalInvocations() >= (oldInvocations + 1)

        when: 'generate a new JWT without kid, JWKS attempt to refresh'
        oldInvocations = totalInvocations()
        googleSignatureConfiguration.clearKid()
        googleAccessToken = accessToken(googleSignatureConfiguration)
        sleep(6_000) // sleep for six seconds so JWKS cache expires
        hello(client, googleAccessToken)

        then:
        totalInvocations() >= (oldInvocations + 1)

        when:
        oldInvocations = totalInvocations()
        String randomSignedJwt = randomSignedJwt()
        hello(client, randomSignedJwt, false)

        then:
        totalInvocations() >= oldInvocations

        when:
        oldInvocations = totalInvocations()
        sleep(6_000) // cache expires the token is still invalid but JWKS attempts to refresh
        hello(client, randomSignedJwt, false)

        then:
        totalInvocations() == (oldInvocations + 3)
    }

    private int totalInvocations() {
        googleInvocations() + appleInvocations() + cognitoInvocations()
    }

    private void assertKeyId(JWT jwt, String keyId) {
        assert jwt instanceof SignedJWT
        assert ((SignedJWT) jwt).getHeader().getKeyID() == keyId
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
        GoogleKeysController(Collection<JwkProvider> jwkProviders, JsonMapper jsonMapper) {
            super(jwkProviders, jsonMapper)
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
        AppleKeysController(Collection<JwkProvider> jwkProviders, JsonMapper jsonMapper) {
            super(jwkProviders, jsonMapper)
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
        CognitoKeysController(Collection<JwkProvider> jwkProviders, JsonMapper jsonMapper) {
            super(jwkProviders, jsonMapper)
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
    @Named("generator")
    @Singleton
    static class AppleSignatureConfiguration extends TestSignatureConfiguration {
        AppleSignatureConfiguration() {
            super('apple')
        }
    }

    @Requires(property = 'spec.name', value = 'CognitoJwksCacheSpec')
    @Named("generator")
    @Singleton
    static class CognitoSignatureConfiguration extends TestSignatureConfiguration {
        CognitoSignatureConfiguration() {
            super('cognito')
        }

        void rotateKid() {
            rotateKid('cognito')
        }
    }

    @Requires(property = 'spec.name', value = 'GoogleJwksCacheSpec')
    @Named("generator")
    @Singleton
    static class GoogleSignatureConfiguration extends TestSignatureConfiguration {
        GoogleSignatureConfiguration() {
            super('google')
        }

        void clearKid() {
            super.clearKid()
        }
    }

    private static abstract class TestSignatureConfiguration implements RSASignatureGeneratorConfiguration, JwkProvider {
        private final static JWSAlgorithm ALG = JWSAlgorithm.RS256
        private List<JWK> jwks
        private RSAKey rsaKey
        String kid

        TestSignatureConfiguration(String kid) {
            this.kid = kid
            refreshKey()
        }

        void rotateKid(String prefix) {
            this.kid = prefix + '-' + UUID.randomUUID().toString().substring(0, 5)
            refreshKey()
        }

        void clearKid() {
            this.kid = null
            refreshKey()
        }

        void refreshKey() {
            JWKGenerator jwkGenerator = new RSAKeyGenerator(2048)
                    .algorithm(ALG)
                    .keyUse(KeyUse.SIGNATURE)
            if (kid) {
                jwkGenerator = jwkGenerator.keyID(kid)
            }
            this.rsaKey = jwkGenerator.generate()
            this.jwks = Collections.singletonList(rsaKey.toPublicJWK())
        }

        List<JWK> getJwks() {
            return jwks
        }

        RSAKey getRsaKey() {
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


    private int googleInvocations() {
        googleEmbeddedServer.applicationContext.getBean(GoogleKeysController).invocations
    }

    private int appleInvocations() {
        appleEmbeddedServer.applicationContext.getBean(AppleKeysController).invocations
    }

    private int cognitoInvocations() {
        cognitoEmbeddedServer.applicationContext.getBean(CognitoKeysController).invocations
    }

    private static String accessToken(TestSignatureConfiguration signatureConfiguration) {
        RSAKey rsaKey = signatureConfiguration.rsaKey
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject('sherlock')
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + 300_000))
                .build()
        JWSHeader.Builder header = new JWSHeader.Builder(signatureConfiguration.jwsAlgorithm)
        if (rsaKey.keyID) {
            header = header.keyID(rsaKey.keyID)
        }
        SignedJWT signedJWT = new SignedJWT(header.build(), claimsSet)
        signedJWT.sign(new RSASSASigner(rsaKey.toPrivateKey()))
        String token = signedJWT.serialize()
        assert token : 'Expected JWKS cache test fixture to generate a signed access token'
        token
    }

    private static String randomSignedJwt() {
        SecureRandom random = new SecureRandom()
        byte[] sharedSecret = new byte[32]
        random.nextBytes(sharedSecret)
        JWSSigner signer = new MACSigner(sharedSecret)
        JWSObject jwsObject = new JWSObject(new JWSHeader(JWSAlgorithm.HS256), new Payload('{"username": "sherlock"}'))
        jwsObject.sign(signer)
        jwsObject.serialize()
    }

}
