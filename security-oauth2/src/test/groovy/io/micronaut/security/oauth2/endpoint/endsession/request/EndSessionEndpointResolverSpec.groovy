package io.micronaut.security.oauth2.endpoint.endsession.request

import groovy.transform.AutoImplement
import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpMethod
import io.micronaut.http.HttpRequest
import io.micronaut.http.simple.SimpleHttpRequest
import io.micronaut.inject.qualifiers.Qualifiers
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.context.ServerRequestContextSecurityContextSupplier
import io.micronaut.security.oauth2.client.OpenIdProviderMetadata
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration
import io.micronaut.security.oauth2.endpoint.endsession.response.EndSessionCallbackUrlBuilder
import io.micronaut.security.testutils.ApplicationContextSpecification
import jakarta.inject.Named
import jakarta.inject.Singleton
import spock.lang.Shared

class EndSessionEndpointResolverSpec extends ApplicationContextSpecification {

    @Override
    String getSpecName() {
        'EndSessionEndpointResolverSpec'
    }

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.authentication': 'idtoken',
        ]
    }

    @Shared
    EndSessionEndpointResolver endSessionEndpointResolver = applicationContext.getBean(EndSessionEndpointResolver)

    @Shared
    EndSessionCallbackUrlBuilder endSessionCallbackUrlBuilder = applicationContext.getBean(EndSessionCallbackUrlBuilder)

    @Shared
    OauthClientConfiguration oauthClientConfiguration = applicationContext.getBean(OauthClientConfiguration, Qualifiers.byName("okta"))

    @Shared
    OpenIdProviderMetadata openIdProviderMetadata = applicationContext.getBean(OpenIdProviderMetadata, Qualifiers.byName("okta"))


    void "Okta end session endpoint resolves id token from request"() {
        when:
        Optional<EndSessionEndpoint> endSessionEndpointOptional = endSessionEndpointResolver.resolve(oauthClientConfiguration, openIdProviderMetadata, endSessionCallbackUrlBuilder)

        then:
        endSessionEndpointOptional.isPresent()

        when:
        EndSessionEndpoint endSessionEndpoint = endSessionEndpointOptional.get()

        then:
        endSessionEndpoint instanceof OktaEndSessionEndpoint

        when: 'a bearer token is present in the request but it did not authenticate the request'
        HttpRequest<?> request = new SimpleHttpRequest<>(HttpMethod.GET, "http://localhost:8080/oauth/logout", null)
        request.bearerAuth('xxx.yyy.zzz')
        String url = endSessionEndpoint.getUrl(request, Authentication.build("sherlock"))

        then: 'the token is not sent as id_token_hint'
        url == 'https://dev-33333.oktapreview.com/oauth2/default/v1/logout?post_logout_redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Flogout'

        when: 'the request was authenticated with an ID token'
        ServerRequestContextSecurityContextSupplier.getSecurityContext(request).withToken('aaa.bbb.ccc')
        url = endSessionEndpoint.getUrl(request, Authentication.build("sherlock"))

        then: 'only the token which authenticated the request is sent as id_token_hint'
        url == 'https://dev-33333.oktapreview.com/oauth2/default/v1/logout?id_token_hint=aaa.bbb.ccc&post_logout_redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Flogout'
    }

    @Requires(property = 'spec.name', value = 'EndSessionEndpointResolverSpec')
    @Singleton
    @Named("okta")
    @AutoImplement
    static class CustomOauthClientConfiguration implements OauthClientConfiguration {

        @Override
        String getName() {
            return "okta"
        }

        @Override
        Optional<OpenIdClientConfiguration> getOpenid() {
            return Optional.of(new CustomOpenIdClientConfiguration())
        }
    }

    @AutoImplement
    static class CustomOpenIdClientConfiguration implements OpenIdClientConfiguration {

        @Override
        Optional<URL> getIssuer() {
            return Optional.of(new URL("https://dev-33333.oktapreview.com/oauth2/default"))
        }

        @Override
        String getName() {
            return "okta"
        }
    }

    @Requires(property = 'spec.name', value = 'EndSessionEndpointResolverSpec')
    @Named("okta")
    @Singleton
    @AutoImplement
    static class CustomOpenIdProviderMetadata implements OpenIdProviderMetadata {

        @Override
        String getIssuer() {
            "https://dev-33333.oktapreview.com/oauth2/default"
        }

        @Override
        String getEndSessionEndpoint() {
            "https://dev-33333.oktapreview.com/oauth2/default/v1/logout"
        }
    }
}
