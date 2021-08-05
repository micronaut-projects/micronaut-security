package io.micronaut.security.handlers

import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Produces
import io.micronaut.security.annotation.Secured
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.testutils.EmbeddedServerSpecification
import io.micronaut.security.testutils.authprovider.MockAuthenticationProvider
import io.micronaut.security.testutils.authprovider.SuccessAuthenticationScenario
import jakarta.inject.Singleton
import spock.lang.Shared

class RedirectRejectionHandlerSpec extends EmbeddedServerSpecification {

    @Override
    String getSpecName() {
        "RedirectRejectionHandlerSpec"
    }

    @Shared
    String accept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"

    Map<String, Object> getConfiguration() {
        super.configuration + ['micronaut.security.redirect.unauthorized.url': '/login',
                               'micronaut.security.redirect.forbidden.url': '/forbidden']
    }

    void "UnauthorizedRejectionUriProvider is used for 401"() {
        when: 'accessing a secured page without authenticating'
        HttpRequest request = HttpRequest.GET("/secured").header("Accept", accept)
        HttpResponse<String> rsp = client.exchange(request, String)

        then: 'user is redirected to the url provided by CustomUnauthorizedRejectionUriProvider'
        rsp.status() == HttpStatus.OK
        rsp.body() == 'login'
    }

    def "ForbiddenRejectionUriProvider is used for 401"() {
        when: 'accessing a secured page authenticating'
        HttpRequest request = HttpRequest.GET("/secured")
                .header("Accept", accept)
                .basicAuth("sherlock", "elementary")
        HttpResponse<String> rsp = client.exchange(request, String)

        then: 'no redirection takes place'
        rsp.status() == HttpStatus.OK
        rsp.body() == 'secured'

        when: 'accessing a restricted page without authentication but without required roles'
        request = HttpRequest.GET("/admin")
                .header("Accept", accept)
                .basicAuth("sherlock", "elementary")
        rsp = client.exchange(request, String)

        then: 'user is redirected to the url provided by ForbiddenRejectionUriProvider'
        rsp.status() == HttpStatus.OK
        rsp.body() == 'forbidden'
    }

    @Requires(property = "spec.name", value = "RedirectRejectionHandlerSpec")
    @Controller("/")
    static class HomeController {

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Produces(MediaType.TEXT_PLAIN)
        @Get
        String index() {
            'open'
        }

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Produces(MediaType.TEXT_PLAIN)
        @Get("/login")
        String login() {
            'login'
        }

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Produces(MediaType.TEXT_PLAIN)
        @Get("/forbidden")
        String forbidden() {
            'forbidden'
        }

        @Secured(SecurityRule.IS_AUTHENTICATED)
        @Produces(MediaType.TEXT_PLAIN)
        @Get("/secured")
        String secured() {
            'secured'
        }

        @Secured("ROLE_ADMIN")
        @Produces(MediaType.TEXT_PLAIN)
        @Get("/admin")
        String admin() {
            'admin'
        }
    }

    @Requires(property = "spec.name", value = "RedirectRejectionHandlerSpec")
    @Singleton
    static class CustomAuthenticationProvider extends MockAuthenticationProvider {
        CustomAuthenticationProvider() {
            super([new SuccessAuthenticationScenario('sherlock')])
        }
    }

}
