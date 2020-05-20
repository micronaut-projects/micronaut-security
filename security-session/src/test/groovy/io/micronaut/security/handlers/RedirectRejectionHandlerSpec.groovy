package io.micronaut.security.handlers

import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Produces
import io.micronaut.security.EmbeddedServerSpecification
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.AuthenticationProvider
import io.micronaut.security.authentication.AuthenticationRequest
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.authentication.UserDetails
import io.micronaut.security.rules.SecurityRule
import io.reactivex.BackpressureStrategy
import io.reactivex.Flowable
import org.reactivestreams.Publisher
import spock.lang.Shared

import javax.inject.Singleton

class RedirectRejectionHandlerSpec extends EmbeddedServerSpecification {

    @Override
    String getSpecName() {
        "RedirectRejectionHandlerSpec"
    }

    @Shared
    String accept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"

    Map<String, Object> getConfiguration() {
        super.configuration + ['micronaut.security.redirect.unauthorized': '/login',
                               'micronaut.security.redirect.forbidden': '/forbidden']
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
    static class CustomAuthenticationProvider implements AuthenticationProvider {

        @Override
        Publisher<AuthenticationResponse> authenticate(HttpRequest<?> httpRequest, AuthenticationRequest<?, ?> authenticationRequest) {
            Flowable.create({emitter ->
                emitter.onNext(new UserDetails("sherlock", Collections.emptyList()))
                emitter.onComplete()
            }, BackpressureStrategy.ERROR)
        }
    }

}
