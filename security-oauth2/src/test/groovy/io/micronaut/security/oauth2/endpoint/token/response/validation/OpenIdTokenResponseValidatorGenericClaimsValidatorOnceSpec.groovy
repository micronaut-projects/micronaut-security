package io.micronaut.security.oauth2.endpoint.token.response.validation

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jwt.JWT
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import io.micronaut.context.annotation.Primary
import io.micronaut.context.annotation.Replaces
import io.micronaut.context.annotation.Requires
import io.micronaut.core.annotation.Order
import io.micronaut.core.order.Ordered
import io.micronaut.http.HttpRequest
import io.micronaut.http.context.ServerRequestContext
import io.micronaut.security.oauth2.client.OpenIdProviderMetadata
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdTokenResponse
import io.micronaut.security.testutils.ApplicationContextSpecification
import io.micronaut.security.token.Claims
import io.micronaut.security.token.jwt.signature.jwks.DefaultJwkSetFetcher
import io.micronaut.security.token.jwt.signature.jwks.JwkSetFetcher
import io.micronaut.security.token.jwt.validator.GenericJwtClaimsValidator
import jakarta.inject.Singleton
import org.jspecify.annotations.NonNull
import org.jspecify.annotations.Nullable
import org.reactivestreams.Publisher
import reactor.core.publisher.Mono

import java.time.Instant
import java.util.concurrent.CopyOnWriteArrayList
import java.util.function.Supplier

/**
 * Verifies that every {@link GenericJwtClaimsValidator} bean is invoked exactly once per ID token validation, with the
 * current HTTP request, regardless of whether the OpenID specific validations succeed or fail afterwards.
 */
class OpenIdTokenResponseValidatorGenericClaimsValidatorOnceSpec extends ApplicationContextSpecification {

    private static final String ISSUER = 'https://issuer.example.com'
    private static final String CLIENT_ID = 'client-id'
    private static final String NONCE = 'expected-nonce'
    private static final RSAKey RSA_KEY = new RSAKeyGenerator(2048).keyID('once-spec').algorithm(JWSAlgorithm.RS256).generate()

    @Override
    String getSpecName() {
        'OpenIdTokenResponseValidatorGenericClaimsValidatorOnceSpec'
    }

    void setup() {
        applicationContext.getBean(CountingGenericJwtClaimsValidator).reset()
    }

    void "generic JWT claim validators run exactly once with the current request when the ID token is valid"() {
        given:
        CountingGenericJwtClaimsValidator counting = applicationContext.getBean(CountingGenericJwtClaimsValidator)
        ReactiveOpenIdTokenResponseValidator<JWT> validator = applicationContext.getBean(ReactiveOpenIdTokenResponseValidator)
        OpenIdTokenResponse tokenResponse = tokenResponse()
        HttpRequest<?> request = HttpRequest.GET('/oauth/callback/foo')

        when:
        Optional<JWT> result = ServerRequestContext.with(request, {
            Mono.from(validator.validate(clientConfiguration(), providerMetadata(), tokenResponse, NONCE)).blockOptional()
        } as Supplier<Optional<JWT>>)

        then:
        result.isPresent()
        counting.requests.size() == 1
        counting.requests[0] != null
        counting.requests[0].is(request)
    }

    void "generic JWT claim validators are not re-run when the OpenID specific validation fails"() {
        given:
        CountingGenericJwtClaimsValidator counting = applicationContext.getBean(CountingGenericJwtClaimsValidator)
        ReactiveOpenIdTokenResponseValidator<JWT> validator = applicationContext.getBean(ReactiveOpenIdTokenResponseValidator)
        OpenIdTokenResponse tokenResponse = tokenResponse()
        HttpRequest<?> request = HttpRequest.GET('/oauth/callback/foo')

        when:
        Optional<JWT> result = ServerRequestContext.with(request, {
            Mono.from(validator.validate(clientConfiguration(), providerMetadata(), tokenResponse, 'a-different-nonce')).blockOptional()
        } as Supplier<Optional<JWT>>)

        then:
        result.isEmpty()
        counting.requests.size() == 1
        counting.requests[0].is(request)
    }

    private OpenIdTokenResponse tokenResponse() {
        // since 5.5.2 the ID token is verified exclusively against the JWKS of the provider
        SignedJWT signedJwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(RSA_KEY.keyID).build(), new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .audience(CLIENT_ID)
                .subject('sherlock')
                .claim('nonce', NONCE)
                .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
                .build())
        signedJwt.sign(new RSASSASigner(RSA_KEY))
        OpenIdTokenResponse tokenResponse = new OpenIdTokenResponse()
        tokenResponse.idToken = signedJwt.serialize()
        tokenResponse
    }

    private OauthClientConfiguration clientConfiguration() {
        Stub(OauthClientConfiguration) {
            getClientId() >> CLIENT_ID
            getName() >> 'myprovider'
        }
    }

    private OpenIdProviderMetadata providerMetadata() {
        Stub(OpenIdProviderMetadata) {
            getIssuer() >> ISSUER
            getJwksUri() >> (ISSUER + '/jwks')
        }
    }

    @Requires(property = 'spec.name', value = 'OpenIdTokenResponseValidatorGenericClaimsValidatorOnceSpec')
    @Singleton
    static class CountingGenericJwtClaimsValidator implements GenericJwtClaimsValidator<HttpRequest<?>> {

        final List<HttpRequest<?>> requests = new CopyOnWriteArrayList<>()

        @Override
        boolean validate(@NonNull Claims claims, @Nullable HttpRequest<?> request) {
            requests.add(request)
            true
        }

        void reset() {
            requests.clear()
        }
    }

    @Singleton
    @Primary
    @Order(Ordered.HIGHEST_PRECEDENCE)
    @Replaces(DefaultJwkSetFetcher)
    @Requires(property = 'spec.name', value = 'OpenIdTokenResponseValidatorGenericClaimsValidatorOnceSpec')
    static class StaticJwkSetFetcher implements JwkSetFetcher<JWKSet> {

        @Override
        Publisher<JWKSet> fetch(String providerName, String url) {
            Mono.just(new JWKSet(RSA_KEY.toPublicJWK()))
        }

        @Override
        void clearCache(String url) {
        }
    }
}
