package io.micronaut.security.endpoints.introspection

import io.micronaut.http.HttpRequest
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.token.config.TokenConfigurationProperties
import io.micronaut.security.token.validator.TokenValidator
import io.micronaut.serde.ObjectMapper
import org.jspecify.annotations.NonNull
import org.jspecify.annotations.Nullable
import org.reactivestreams.Publisher
import reactor.core.publisher.Mono
import spock.lang.Specification

class DefaultIntrospectionProcessorNullAttributesSpec extends Specification {

    void "attributes present with a null value are treated as absent instead of throwing NullPointerException"() {
        given: 'an Authentication whose attributes map contains null values for every RFC 7662 field and a custom extension'
        Map<String, Object> attributes = new HashMap<>()
        attributes.put(DefaultIntrospectionProcessor.USERNAME, null)
        attributes.put(DefaultIntrospectionProcessor.SCOPE, null)
        attributes.put(DefaultIntrospectionProcessor.CLIENT_ID, null)
        attributes.put(DefaultIntrospectionProcessor.TOKEN_TYPE, null)
        attributes.put(DefaultIntrospectionProcessor.EXP, null)
        attributes.put(DefaultIntrospectionProcessor.ISSUED_AT, null)
        attributes.put(DefaultIntrospectionProcessor.NOT_BEFORE, null)
        attributes.put(DefaultIntrospectionProcessor.SUBJECT, null)
        attributes.put(DefaultIntrospectionProcessor.AUDIENCE, null)
        attributes.put(DefaultIntrospectionProcessor.ISSUER, null)
        attributes.put(DefaultIntrospectionProcessor.JWT_ID, null)
        attributes.put('refreshToken', null)
        attributes.put('email', 'sherlock@example.com')
        Authentication authentication = Authentication.build('sherlock', ['ROLE_DETECTIVE'], attributes)
        DefaultIntrospectionProcessor<HttpRequest<?>> processor = new DefaultIntrospectionProcessor<>([new FixedAuthenticationTokenValidator(authentication)], new TokenConfigurationProperties(), null)

        when:
        IntrospectionResponse response = Mono.from(processor.introspect(new IntrospectionRequest('token', null), HttpRequest.GET('/token_info'))).block()

        then:
        noExceptionThrown()
        response.active

        and: 'null-valued fields fall back to the same values as absent keys'
        response.username == 'sherlock'
        response.sub == 'sherlock'
        response.scope == null
        response.clientId == null
        response.tokenType == null
        response.exp == null
        response.iat == null
        response.nbf == null
        response.aud == null
        response.iss == null
        response.jti == null

        and: 'null extension values are omitted while non-null ones are kept'
        !response.extensions.containsKey('refreshToken')
        response.extensions['email'] == 'sherlock@example.com'
        response.extensions['roles'] == ['ROLE_DETECTIVE']

        when:
        String json = ObjectMapper.getDefault().writeValueAsString(response)

        then:
        json.contains('"active":true')
        json.contains('"email":"sherlock@example.com"')
        !json.contains('refreshToken')
        !json.contains('null')
    }

    void "secondsSinceEpochOfAttribute returns empty for a null value"() {
        given:
        Map<String, Object> attributes = new HashMap<>()
        attributes.put(DefaultIntrospectionProcessor.EXP, null)
        Authentication authentication = Authentication.build('sherlock', attributes)
        DefaultIntrospectionProcessor<HttpRequest<?>> processor = new DefaultIntrospectionProcessor<>([], new TokenConfigurationProperties(), null)

        expect:
        !processor.secondsSinceEpochOfAttribute(DefaultIntrospectionProcessor.EXP, authentication).isPresent()
        !processor.secondsSinceEpochOfAttribute(DefaultIntrospectionProcessor.ISSUED_AT, authentication).isPresent()
    }

    static class FixedAuthenticationTokenValidator implements TokenValidator<HttpRequest<?>> {

        private final Authentication authentication

        FixedAuthenticationTokenValidator(Authentication authentication) {
            this.authentication = authentication
        }

        @Override
        Publisher<Authentication> validateToken(@NonNull String token, @Nullable HttpRequest<?> request) {
            Mono.just(authentication)
        }
    }
}
