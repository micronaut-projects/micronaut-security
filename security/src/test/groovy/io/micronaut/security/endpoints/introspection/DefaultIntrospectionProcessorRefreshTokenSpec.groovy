package io.micronaut.security.endpoints.introspection

import io.micronaut.http.HttpRequest
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.token.config.TokenConfigurationProperties
import io.micronaut.security.token.event.RefreshTokenGeneratedEvent
import io.micronaut.security.token.refresh.RefreshTokenPersistence
import io.micronaut.security.token.validator.RefreshTokenValidator
import io.micronaut.security.token.validator.TokenValidator
import org.jspecify.annotations.NonNull
import org.jspecify.annotations.Nullable
import org.reactivestreams.Publisher
import reactor.core.publisher.Mono
import spock.lang.Specification

import java.util.concurrent.atomic.AtomicInteger

class DefaultIntrospectionProcessorRefreshTokenSpec extends Specification {

    private static final String SIGNED_A = 'signed.key-a'
    private static final String SIGNED_B = 'signed.key-b'

    void "refresh token known to RefreshTokenPersistence is active and response is populated from the persisted Authentication"() {
        given:
        MapRefreshTokenPersistence persistence = new MapRefreshTokenPersistence(['key-a': Authentication.build('alice', ['ROLE_USER'])])
        DefaultIntrospectionProcessor<HttpRequest<?>> processor = new DefaultIntrospectionProcessor<>([], new TokenConfigurationProperties(), new PrefixRefreshTokenValidator(), persistence)

        when:
        IntrospectionResponse response = introspect(processor, SIGNED_A)

        then:
        response.active
        response.username == 'alice'
        response.sub == 'alice'
        response.extensions['roles'] == ['ROLE_USER']
        persistence.lookups == ['key-a']
    }

    void "refresh token unknown to RefreshTokenPersistence (revoked) is inactive even though its signature is valid"() {
        given:
        MapRefreshTokenPersistence persistence = new MapRefreshTokenPersistence(['key-a': Authentication.build('alice')])
        DefaultIntrospectionProcessor<HttpRequest<?>> processor = new DefaultIntrospectionProcessor<>([], new TokenConfigurationProperties(), new PrefixRefreshTokenValidator(), persistence)

        when:
        IntrospectionResponse response = introspect(processor, SIGNED_B)

        then:
        !response.active
        !response.username
        persistence.lookups == ['key-b']
    }

    void "refresh token is inactive when RefreshTokenPersistence errors"() {
        given:
        RefreshTokenPersistence persistence = new RefreshTokenPersistence() {
            @Override
            void persistToken(RefreshTokenGeneratedEvent event) {
            }

            @Override
            Publisher<Authentication> getAuthentication(String refreshToken) {
                Mono.error(new IllegalStateException('database down'))
            }
        }
        DefaultIntrospectionProcessor<HttpRequest<?>> processor = new DefaultIntrospectionProcessor<>([], new TokenConfigurationProperties(), new PrefixRefreshTokenValidator(), persistence)

        when:
        IntrospectionResponse response = introspect(processor, SIGNED_A)

        then:
        noExceptionThrown()
        !response.active
    }

    void "without a RefreshTokenPersistence bean a refresh token with a valid signature is reported active but no fields are populated"() {
        // There is no revocation point to consult, so the previous behaviour is kept.
        given:
        PrefixRefreshTokenValidator refreshTokenValidator = new PrefixRefreshTokenValidator()
        DefaultIntrospectionProcessor<HttpRequest<?>> processor = new DefaultIntrospectionProcessor<>([], new TokenConfigurationProperties(), refreshTokenValidator, null)

        when:
        IntrospectionResponse response = introspect(processor, SIGNED_A)

        then:
        response.active
        !response.username
        !response.sub
        response.extensions.isEmpty()
        refreshTokenValidator.invocations.get() == 1
    }

    void "refresh token with an invalid signature is inactive and RefreshTokenPersistence is never consulted"() {
        given:
        MapRefreshTokenPersistence persistence = new MapRefreshTokenPersistence(['key-a': Authentication.build('alice')])
        DefaultIntrospectionProcessor<HttpRequest<?>> processor = new DefaultIntrospectionProcessor<>([], new TokenConfigurationProperties(), new PrefixRefreshTokenValidator(), persistence)

        when:
        IntrospectionResponse response = introspect(processor, 'tampered.key-a')

        then:
        !response.active
        persistence.lookups.isEmpty()
    }

    void "token is inactive when there is neither a RefreshTokenValidator nor a TokenValidator accepting it"() {
        given:
        DefaultIntrospectionProcessor<HttpRequest<?>> processor = new DefaultIntrospectionProcessor<>([new RejectingTokenValidator()], new TokenConfigurationProperties(), null, null)

        when:
        IntrospectionResponse response = introspect(processor, SIGNED_A)

        then:
        !response.active
    }

    void "refresh token path is not executed when a TokenValidator accepts the token"() {
        given:
        PrefixRefreshTokenValidator refreshTokenValidator = new PrefixRefreshTokenValidator()
        MapRefreshTokenPersistence persistence = new MapRefreshTokenPersistence(['key-a': Authentication.build('alice')])
        DefaultIntrospectionProcessor<HttpRequest<?>> processor = new DefaultIntrospectionProcessor<>([new AcceptingTokenValidator()], new TokenConfigurationProperties(), refreshTokenValidator, persistence)

        when:
        IntrospectionResponse response = introspect(processor, SIGNED_A)

        then:
        response.active
        response.username == 'access-token-user'

        and: 'neither the refresh token validator nor the persistence were consulted'
        refreshTokenValidator.invocations.get() == 0
        persistence.lookups.isEmpty()
    }

    void "refresh token path is executed once every TokenValidator emits empty"() {
        given:
        PrefixRefreshTokenValidator refreshTokenValidator = new PrefixRefreshTokenValidator()
        MapRefreshTokenPersistence persistence = new MapRefreshTokenPersistence(['key-a': Authentication.build('alice')])
        DefaultIntrospectionProcessor<HttpRequest<?>> processor = new DefaultIntrospectionProcessor<>([new RejectingTokenValidator()], new TokenConfigurationProperties(), refreshTokenValidator, persistence)

        when:
        IntrospectionResponse response = introspect(processor, SIGNED_A)

        then:
        response.active
        response.username == 'alice'
        refreshTokenValidator.invocations.get() == 1
        persistence.lookups == ['key-a']
    }

    private static IntrospectionResponse introspect(DefaultIntrospectionProcessor<HttpRequest<?>> processor, String token) {
        Mono.from(processor.introspect(new IntrospectionRequest(token, null), HttpRequest.GET('/token_info'))).block()
    }

    /**
     * Stand-in for a signature-only validator such as SignedRefreshTokenGenerator: a token is "validly signed" if it starts
     * with {@code signed.}; the remainder is the key that would be stored in the persistence layer.
     */
    static class PrefixRefreshTokenValidator implements RefreshTokenValidator {

        final AtomicInteger invocations = new AtomicInteger()

        @Override
        Optional<String> validate(@NonNull String refreshToken) {
            invocations.incrementAndGet()
            refreshToken.startsWith('signed.') ? Optional.of(refreshToken.substring('signed.'.length())) : Optional.empty()
        }
    }

    static class MapRefreshTokenPersistence implements RefreshTokenPersistence {

        private final Map<String, Authentication> tokens
        final List<String> lookups = []

        MapRefreshTokenPersistence(Map<String, Authentication> tokens) {
            this.tokens = tokens
        }

        @Override
        void persistToken(RefreshTokenGeneratedEvent event) {
            tokens.put(event.refreshToken, event.authentication)
        }

        @Override
        Publisher<Authentication> getAuthentication(String refreshToken) {
            lookups << refreshToken
            Mono.justOrEmpty(tokens.get(refreshToken))
        }
    }

    static class AcceptingTokenValidator implements TokenValidator<HttpRequest<?>> {
        @Override
        Publisher<Authentication> validateToken(@NonNull String token, @Nullable HttpRequest<?> request) {
            Mono.just(Authentication.build('access-token-user'))
        }
    }

    static class RejectingTokenValidator implements TokenValidator<HttpRequest<?>> {
        @Override
        Publisher<Authentication> validateToken(@NonNull String token, @Nullable HttpRequest<?> request) {
            Mono.empty()
        }
    }
}
