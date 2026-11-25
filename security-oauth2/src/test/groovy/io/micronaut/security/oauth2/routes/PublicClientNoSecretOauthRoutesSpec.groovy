package io.micronaut.security.oauth2.routes

import io.micronaut.security.oauth2.OpenIdMockEmbeddedServerSpecification
import io.micronaut.web.router.RouteBuilder
import spock.lang.Shared
import spock.lang.Unroll

class PublicClientNoSecretOauthRoutesSpec extends OpenIdMockEmbeddedServerSpecification {

    @Shared
    Set<String> paths = applicationContext.getBeansOfType(RouteBuilder).collect { it.uriRoutes }
            .flatten()
            .collect { it.uriMatchTemplate.toPathString() } as Set<String>

    @Override
    Map<String, Object> getOauth2ClientConfiguration() {
        [
                ("micronaut.security.oauth2.clients.${openIdClientName}.client-id".toString()): 'XXXX',
                ("micronaut.security.oauth2.clients.${openIdClientName}.openid.issuer".toString()): issuer,
        ]
    }

    @Unroll
    void "#route is registered for a public OAuth 2.0 application without a client secret"(String route) {
        expect:
        paths.any { it == route }

        where:
        route << [
                '/oauth/callback/foo',
                '/oauth/login/foo']
    }
}
