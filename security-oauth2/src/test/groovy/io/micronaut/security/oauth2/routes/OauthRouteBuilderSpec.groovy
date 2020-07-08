package io.micronaut.security.oauth2.routes

import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.oauth2.OpenIdMockEmbeddedServerSpecification
import io.micronaut.security.oauth2.endpoint.endsession.request.EndSessionEndpoint
import io.micronaut.web.router.RouteBuilder
import spock.lang.Unroll

import javax.inject.Named
import javax.inject.Singleton

class OauthRouteBuilderSpec extends OpenIdMockEmbeddedServerSpecification {

    @Override
    String getSpecName() {
        'OauthRouteBuilderSpec'
    }

    @Unroll
    void "#route is registered"(String route) {
        expect:
        openIdClientName == 'foo'

        when:
        Collection<RouteBuilder> routeBuilders = applicationContext.getBeansOfType(RouteBuilder)
        List<String> paths = routeBuilders.collect { it.uriRoutes }
                .flatten()
                .collect { it.uriMatchTemplate.toPathString() }

        then:
        paths.any { it == route }

        where:
        route << [
                '/oauth/callback/foo',
                '/oauth/login/foo',
                '/oauth/logout'] // providing a EndSessionEndpoint qualified with named `foo` enables endpoint
    }

    @Requires(property = "spec.name", value = 'OauthRouteBuilderSpec')
    @Named("foo")
    @Singleton
    static class CustomEndSessionEndpoint implements EndSessionEndpoint {
        @Override
        String getUrl(HttpRequest<?> originating, Authentication authentication) {
            null
        }
    }
}
