package io.micronaut.security.token.jwt.cookie

import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.MediaType
import io.micronaut.http.client.BlockingHttpClient
import io.micronaut.http.client.HttpClient
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.testutils.authprovider.MockAuthenticationProvider
import io.micronaut.security.testutils.authprovider.SuccessAuthenticationScenario
import jakarta.inject.Singleton
import spock.lang.Specification

class JwtCookieSameSiteCaseSensitiveSpec extends Specification {

    void "same-site is case sensitive"(String sameSiteValue, String expected) {
        given:
        EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer, [
                'spec.name': 'JwtCookieSameSiteCaseSensitiveSpec',
                'micronaut.http.client.followRedirects': false,
                'micronaut.security.authentication': 'cookie',
                'micronaut.security.token.jwt.cookie.cookie-same-site': sameSiteValue,
        ])
        ApplicationContext applicationContext = embeddedServer.applicationContext
        HttpClient httpClient = applicationContext.createBean(HttpClient, embeddedServer.URL)
        BlockingHttpClient client = httpClient.toBlocking()

        when:
        HttpRequest loginRequest = HttpRequest.POST('/login', new LoginForm(username: 'sherlock', password: 'password'))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE)
        HttpResponse loginRsp = client.exchange(loginRequest, String)

        then:
        noExceptionThrown()

        when:
        String cookie = loginRsp.getHeaders().get('Set-Cookie')

        then:
        if (expected) {
            assert cookie.contains(expected)
        } else {
            assert !cookie.contains('SameSite')
        }

        cleanup:
        httpClient.close()
        applicationContext.close()
        embeddedServer.close()

        where:
        sameSiteValue || expected
        'Strict'      || 'SameSite=Strict'
        'strict'      || null
        'Lax'         || 'SameSite=Lax'
        'None'        || 'SameSite=None'
    }

    @Requires(property = "spec.name", value = "JwtCookieSameSiteCaseSensitiveSpec")
    @Singleton
    static class AuthenticationProviderUserPassword extends MockAuthenticationProvider  {
        AuthenticationProviderUserPassword() {
            super([new SuccessAuthenticationScenario( "sherlock")])
        }
    }
}
