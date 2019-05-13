package io.micronaut.security.oauth2.routes

import io.micronaut.security.oauth2.ApplicationContextSpecification
import io.micronaut.web.router.RouteBuilder
import spock.lang.Unroll

class OauthRouteBuilderSpec extends ApplicationContextSpecification {

    @Unroll
    void "#route is registered"(String route) {
        when:
        Collection<RouteBuilder> routeBuilders = applicationContext.getBeansOfType(RouteBuilder)
        List<String> paths = routeBuilders.collect { it.uriRoutes }.flatten().collect { it.uriMatchTemplate.toPathString() }

        then:
        paths.any { it == route }

        cleanup:
        applicationContext.close()

        where:
        route << [
                '/oauth/callback/foo',
                '/oauth/login/foo',
                '/oauth/logout']
    }
}
