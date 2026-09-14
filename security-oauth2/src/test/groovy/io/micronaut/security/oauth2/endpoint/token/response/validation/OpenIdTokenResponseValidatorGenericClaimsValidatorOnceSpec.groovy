package io.micronaut.security.oauth2.endpoint.token.response.validation

import com.nimbusds.jwt.JWT
import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.context.ServerRequestContext
import io.micronaut.security.oauth2.client.OpenIdProviderMetadata
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdTokenResponse
import io.micronaut.security.testutils.ApplicationContextSpecification
import io.micronaut.security.token.Claims
import io.micronaut.security.token.jwt.generator.JwtTokenGenerator
import io.micronaut.security.token.jwt.validator.GenericJwtClaimsValidator
import jakarta.inject.Singleton
import org.jspecify.annotations.NonNull
import org.jspecify.annotations.Nullable
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

    @Override
    String getSpecName() {
        'OpenIdTokenResponseValidatorGenericClaimsValidatorOnceSpec'
    }

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.token.jwt.signatures.secret.generator.secret': 'pleaseChangeThisSecretForANewOne',
        ]
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
        JwtTokenGenerator tokenGenerator = applicationContext.getBean(JwtTokenGenerator)
        OpenIdTokenResponse tokenResponse = new OpenIdTokenResponse()
        tokenResponse.idToken = tokenGenerator.generateToken([
                iss  : ISSUER,
                aud  : CLIENT_ID,
                sub  : 'sherlock',
                nonce: NONCE,
                exp  : Instant.now().plusSeconds(3600).epochSecond,
        ]).get()
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
}
