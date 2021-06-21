package io.micronaut.security.authorization

import io.micronaut.core.annotation.Nullable
import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.management.endpoint.annotation.Endpoint
import io.micronaut.management.endpoint.annotation.Read
import io.micronaut.security.testutils.EmbeddedServerSpecification

import java.security.Principal

class AuthorizationWithoutInterceptUrlMapSpec extends EmbeddedServerSpecification {

    @Override
    String getSpecName() {
        'AuthorizationWithoutInterceptUrlMapSpec'
    }

    void "test accessing a non sensitive endpoint without authentication"() {
        when:
        HttpResponse<String> response = client.exchange(HttpRequest.GET("/non-sensitive"), String)

        then:
        response.body() == "Not logged in"
    }

    void "test accessing a sensitive endpoint without authentication"() {
        when:
        client.exchange(HttpRequest.GET("/sensitive"), String)

        then:
        HttpClientResponseException e = thrown(HttpClientResponseException)
        e.status == HttpStatus.UNAUTHORIZED
    }

    @Requires(property = 'spec.name', value = 'AuthorizationWithoutInterceptUrlMapSpec')
    @Endpoint(id = "nonSensitive", defaultSensitive = false)
    static class NonSensitiveEndpoint {

        @Read
        String hello(@Nullable Principal principal) {
            if (principal == null) {
                "Not logged in"
            } else {
                "Logged in as ${principal.name}"
            }
        }
    }

    @Requires(property = 'spec.name', value = 'AuthorizationWithoutInterceptUrlMapSpec')
    @Endpoint(id = "sensitive", defaultSensitive = true)
    static class SensitiveEndpoint {

        @Read
        String hello(Principal principal) {
            "Hello ${principal.name}"
        }
    }
}
