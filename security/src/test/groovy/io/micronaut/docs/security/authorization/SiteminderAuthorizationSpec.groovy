package io.micronaut.docs.security.authorization

import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.client.HttpClient
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.rules.SecurityRule
import spock.lang.Specification

import static io.micronaut.docs.security.authorization.SiteminderAuthenticationFetcher.SITEMINDER_USER_HEADER

class SiteminderAuthorizationSpec extends Specification {

    void 'test custom SiteMinder authentication fetcher'() {
        given:
        String username = UUID.randomUUID()
        EmbeddedServer server = ApplicationContext.run(EmbeddedServer, [
                'spec.name': SiteminderAuthorizationSpec.simpleName])

        when:
        HttpClient client = server.applicationContext.createBean(HttpClient, server.URL)
        HttpRequest request = HttpRequest.GET('/sm').header(SITEMINDER_USER_HEADER, username)

        then:
        client.toBlocking().retrieve(request) == username
    }

    @Requires(property = 'spec.name', value = 'SiteminderAuthorizationSpec')
    @Secured(SecurityRule.IS_AUTHENTICATED)
    @Controller('/sm')
    static class MyController {
        @Get
        String username(Authentication authentication) {
            authentication.name
        }
    }
}
