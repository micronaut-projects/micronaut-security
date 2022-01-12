package io.micronaut.docs.security.authorization

import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Produces
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.testutils.EmbeddedServerSpecification

import static io.micronaut.docs.security.authorization.SiteminderAuthenticationFetcher.SITEMINDER_USER_HEADER

class SiteminderAuthorizationSpec extends EmbeddedServerSpecification {
    @Override
    String getSpecName() {
        'SiteminderAuthorizationSpec'
    }

    void 'test custom SiteMinder authentication fetcher'() {
        given:
        String username = UUID.randomUUID()

        when:
        HttpRequest request = HttpRequest.GET('/sm').header(SITEMINDER_USER_HEADER, username)

        then:
        client.retrieve(request) == username
    }

    @Requires(property = 'spec.name', value = 'SiteminderAuthorizationSpec')
    @Secured(SecurityRule.IS_AUTHENTICATED)
    @Controller('/sm')
    static class MyController {
        @Produces(MediaType.TEXT_PLAIN)
        @Get
        String username(Authentication authentication) {
            authentication.name
        }
    }
}
