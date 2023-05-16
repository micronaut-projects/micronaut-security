package io.micronaut.security.docs.securedexpressions

import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpStatus
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.testutils.authprovider.MockAuthenticationProvider
import io.micronaut.security.testutils.authprovider.SuccessAuthenticationScenario
import jakarta.inject.Singleton
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification

class SecuredExpressionsSpec extends Specification {
    @Shared
    Map<String, Object> config = [
            'spec.name': 'docexpressions'
    ]

    @Shared
    @AutoCleanup
    EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer, config as Map<String, Object>)

    @Shared
    @AutoCleanup
    HttpClient client = embeddedServer.applicationContext.createBean(HttpClient, embeddedServer.getURL())

    void "verify you can access an endpoint annotated with @Secured() expression with an authenticated user"() {
        when:
        client.toBlocking().exchange(HttpRequest.GET("/authenticated/principal").basicAuth("watson", "password"))

        then:
        HttpClientResponseException e = thrown()
        e.status == HttpStatus.UNAUTHORIZED

        when:
        client.toBlocking().exchange(HttpRequest.GET("/authenticated/email").basicAuth("sherlock", "password"))

        then:
        noExceptionThrown()

        when:
        client.toBlocking().exchange(HttpRequest.GET("/authenticated/email").basicAuth("moriarty", "password"))

        then:
        e = thrown()
        e.status == HttpStatus.FORBIDDEN

        when:
        client.toBlocking().exchange(HttpRequest.GET("/authenticated/email").basicAuth("watson", "password"))

        then:
        e = thrown()
        e.status == HttpStatus.UNAUTHORIZED
    }

    @Singleton
    @Requires(property = 'spec.name', value = 'docexpressions')
    static class AuthenticationProviderUserPassword extends MockAuthenticationProvider {
        AuthenticationProviderUserPassword() {
            super([new SuccessAuthenticationScenario('sherlock', ['ROLE_ADMIN'], [email: 'sherlock@micronaut.example']),
                   new SuccessAuthenticationScenario('moriarty', ['ROLE_ADMIN'], [email: 'moriarty@micronaut.example'])])
        }
    }
}
