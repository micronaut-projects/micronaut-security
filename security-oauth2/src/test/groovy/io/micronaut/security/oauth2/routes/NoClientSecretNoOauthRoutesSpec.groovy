package io.micronaut.security.oauth2.routes

import io.micronaut.security.oauth2.OpenIdMockEmbeddedServerSpecification
import io.micronaut.web.router.RouteBuilder
import spock.lang.Narrative
import spock.lang.Shared
import spock.lang.Unroll

@Narrative('''
For a config such as: 

micronaut:
  security:
    oauth2:
      clients:
        foo:
          client-id: 'XXX'
          openid:
            issuer: 'blababla'
        bar:   
          client-id: 'XXX'
          client-secret: 'YYY'
          openid:
            issuer: 'blababla'
            
Micronaut creates routes ('/oauth/callback/{name}','/oauth/login/{name}',) for OAuth 2.0 applications with a client secret.                      
''')
class NoClientSecretNoOauthRoutesSpec extends OpenIdMockEmbeddedServerSpecification {

    @Shared
    Set<String> paths = applicationContext.getBeansOfType(RouteBuilder).collect { it.uriRoutes }
            .flatten()
            .collect { it.uriMatchTemplate.toPathString() } as Set<String>

    @Override
    String getClientSecret() {
        null
    }

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
            "micronaut.security.oauth2.clients.bar.client-id": 'XXXX',
            "micronaut.security.oauth2.clients.bar.client-secret": 'YYYY',
            "micronaut.security.oauth2.clients.bar.openid.issuer": issuer
        ]
    }

    @Unroll
    void "#route is not registered because no client secret is specified for OAuth 2.0 application"(String route) {
        expect:
        paths.every { it != route }

        where:
        route << [
                '/oauth/callback/foo',
                '/oauth/login/foo',
                '/oauth/logout']
    }

    @Unroll
    void "#route is registered because client id and client secret are specified for OAuth 2.0 application"(String route) {
        expect:
        paths.any { it == route }

        where:
        route << [
                '/oauth/callback/bar',
                '/oauth/login/bar']
    }


}
