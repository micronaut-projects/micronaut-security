package io.micronaut.security.docs.sensitiveendpointrule

import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpStatus
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.security.testutils.EmbeddedServerSpecification
import io.micronaut.security.testutils.authprovider.MockAuthenticationProvider
import io.micronaut.security.testutils.authprovider.SuccessAuthenticationScenario
import jakarta.inject.Singleton

class SensitiveEndpointRuleReplacementSpec extends EmbeddedServerSpecification {
    @Override
    String getSpecName() {
        'SensitiveEndpointRuleReplacementSpec'
    }

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'endpoints.beans.enabled'    : true,
                'endpoints.sensitive.enabled': true
        ]
    }

    void "test accessing a sensitive endpoint with authentication and a SensitiveEndpointRule replacement works"() {
        when:
        client.exchange(HttpRequest.GET("/beans"))

        then:
        HttpClientResponseException e = thrown(HttpClientResponseException)
        e.status == HttpStatus.UNAUTHORIZED

        when:
        client.exchange(HttpRequest.GET("/beans").basicAuth("user", "password"))

        then:
        noExceptionThrown()
    }

    @Singleton
    @Requires(property = 'spec.name', value = 'SensitiveEndpointRuleReplacementSpec')
    static class AuthenticationProviderUserPassword extends MockAuthenticationProvider {
        AuthenticationProviderUserPassword() {
            super([new SuccessAuthenticationScenario('user')])
        }
    }
}