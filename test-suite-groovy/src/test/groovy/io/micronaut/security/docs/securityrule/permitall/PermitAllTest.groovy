package io.micronaut.security.docs.securityrule.permitall

import io.micronaut.context.annotation.Property
import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpStatus
import io.micronaut.http.client.BlockingHttpClient
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.annotation.Client
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.security.authentication.AuthenticationFailureReason
import io.micronaut.security.authentication.AuthenticationRequest
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.authentication.provider.HttpRequestAuthenticationProvider
import io.micronaut.test.extensions.spock.annotation.MicronautTest
import jakarta.inject.Inject
import jakarta.inject.Singleton
import spock.lang.Specification

@Property(name = "spec.name", value = "PermitAllTest")
@MicronautTest
class PermitAllTest extends Specification {

    @Inject
    @Client("/")
    HttpClient httpClient

    void "permit all endpoint can be accessed without authentication"() {
        when:
        httpClient.toBlocking().exchange(HttpRequest.GET("/example/anonymous"))

        then:
        noExceptionThrown()
    }

    void "roles allowed endpoint requires one of the roles"() {
        given:
        BlockingHttpClient client = httpClient.toBlocking()

        when:
        client.exchange(HttpRequest.GET("/example/admin"))

        then:
        HttpClientResponseException e = thrown()
        e.status == HttpStatus.UNAUTHORIZED

        when:
        client.exchange(HttpRequest.GET("/example/admin").basicAuth("user", "password"))

        then:
        e = thrown()
        e.status == HttpStatus.FORBIDDEN

        when:
        client.exchange(HttpRequest.GET("/example/admin").basicAuth("admin", "password"))

        then:
        noExceptionThrown()
    }

    @Requires(property = "spec.name", value = "PermitAllTest")
    @Singleton
    static class AuthenticationProviderUserPassword<B> implements HttpRequestAuthenticationProvider<B> {
        @Override
        AuthenticationResponse authenticate(HttpRequest<B> requestContext, AuthenticationRequest<String, String> authRequest) {
            if (authRequest.identity == "user") {
                return AuthenticationResponse.success("user")
            }
            if (authRequest.identity == "admin") {
                return AuthenticationResponse.success("admin", ["ROLE_ADMIN"])
            }
            AuthenticationResponse.failure(AuthenticationFailureReason.USER_NOT_FOUND)
        }
    }
}
