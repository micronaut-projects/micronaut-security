package io.micronaut.security.token

import io.micronaut.context.annotation.Property
import io.micronaut.context.annotation.Requires
import io.micronaut.core.annotation.Nullable
import io.micronaut.core.async.publisher.Publishers
import io.micronaut.http.HttpHeaders
import io.micronaut.http.HttpMethod
import io.micronaut.http.simple.SimpleHttpRequest
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.token.config.TokenConfiguration
import io.micronaut.security.token.validator.TokenValidator
import io.micronaut.test.extensions.spock.annotation.MicronautTest
import jakarta.inject.Inject
import jakarta.inject.Singleton
import org.reactivestreams.Publisher
import reactor.core.publisher.Mono
import spock.lang.Specification

@Property(name = "spec.name", value = "TokenAuthenticationAttributeNameConfigurableSpec")
@Property(name = "micronaut.security.token.store-as-attribute", value = "true")
@Property(name = "micronaut.security.token.attribute-name", value = "rawToken")
@MicronautTest
class TokenAuthenticationAttributeNameConfigurableSpec extends Specification {

    @Inject
    TokenAuthenticationFetcher tokenAuthenticationFetcher

    @Inject
    TokenConfiguration tokenConfiguration

    void "attribute name is configurable"() {
        when:
        def request = new SimpleHttpRequest(HttpMethod.GET, "/", null)
        request.headers.add(HttpHeaders.AUTHORIZATION, "Bearer yyy")
        Authentication authentication = Mono.from(tokenAuthenticationFetcher.fetchAuthentication(request)).block()

        then:
        tokenConfiguration.attributeName == 'rawToken'
        authentication
        authentication.attributes.get('rawToken') == 'yyy'
    }

    @Requires(property = "spec.name", value = "TokenAuthenticationAttributeNameConfigurableSpec")
    @Singleton
    static class ApiKeyTokenValidator implements TokenValidator {

        @Override
        Publisher<Authentication> validateToken(String token, @Nullable Object request) {
            if (token == 'yyy') {
                return Publishers.just(Authentication.build('foo'))
            }
            return Publishers.empty()
        }
    }
}
