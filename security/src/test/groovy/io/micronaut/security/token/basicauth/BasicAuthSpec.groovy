package io.micronaut.security.token.basicauth

import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpStatus
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.security.MockAuthenticationProvider
import io.micronaut.security.SuccessAuthenticationScenario
import io.micronaut.security.authentication.BasicAuthAuthenticationFetcher
import io.micronaut.security.testutils.EmbeddedServerSpecification
import jakarta.inject.Singleton
class BasicAuthSpec extends EmbeddedServerSpecification {

    @Override
    String getSpecName() {
        'BasicAuthSpec'
    }

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'endpoints.beans.enabled': true,
                'endpoints.beans.sensitive': true,
        ]
    }

    void "test /beans is not accessible if you don't supply Basic Auth in HTTP Header Authorization"() {
        expect:
        embeddedServer.applicationContext.getBean(BasicAuthAuthenticationFetcher.class)
        embeddedServer.applicationContext.getBean(AuthenticationProviderUserPassword.class)

        when:
        String path = "/beans"
        client.exchange(HttpRequest.GET(path), String)

        then:
        HttpClientResponseException e = thrown(HttpClientResponseException)
        e.status == HttpStatus.UNAUTHORIZED
    }

    void "test /beans is not accesible if you don't supply a valid Base64 encoded token in the Basic Auth in HTTP Header Authorization"() {
        expect:
        embeddedServer.applicationContext.getBean(BasicAuthAuthenticationFetcher.class)
        embeddedServer.applicationContext.getBean(AuthenticationProviderUserPassword.class)

        when:
        String token = 'Basic'
        String path = "/beans"
        client.exchange(HttpRequest.GET(path).header("Authorization", "Basic ${token}".toString()), String)

        then:
        HttpClientResponseException e = thrown(HttpClientResponseException)
        e.status == HttpStatus.UNAUTHORIZED
    }

    void "test /beans is secured but accesible if you supply valid credentials with Basic Auth"() {
        expect:
        embeddedServer.applicationContext.getBean(BasicAuthAuthenticationFetcher.class)
        embeddedServer.applicationContext.getBean(AuthenticationProviderUserPassword.class)

        when:
        String token = 'dXNlcjpwYXNzd29yZA==' // user:passsword Base64
        String path = "/beans"
        client.exchange(HttpRequest.GET(path).header("Authorization", "Basic ${token}".toString()), String)

        then:
        noExceptionThrown()
    }

    void "test /beans is not accessible if you valid Base64 encoded token but authentication fails"() {
        expect:
        embeddedServer.applicationContext.getBean(BasicAuthAuthenticationFetcher.class)
        embeddedServer.applicationContext.getBean(AuthenticationProviderUserPassword.class)

        when:
        String token = 'dXNlcjp1c2Vy' // user:user Base64 encoded
        String path = "/beans"
        client.exchange(HttpRequest.GET(path).header("Authorization", "Basic ${token}".toString()), String)

        then:
        HttpClientResponseException e = thrown(HttpClientResponseException)
        e.status == HttpStatus.UNAUTHORIZED
    }

    @Singleton
    @Requires(property = 'spec.name', value = 'BasicAuthSpec')
    static class AuthenticationProviderUserPassword extends MockAuthenticationProvider {
        AuthenticationProviderUserPassword() {
            super([new SuccessAuthenticationScenario('user', 'password')])
        }
    }
}
