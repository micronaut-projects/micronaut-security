package io.micronaut.security.oauth2.endpoint.endsession.request

import groovy.transform.AutoImplement
import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpHeaders
import io.micronaut.http.HttpParameters
import io.micronaut.http.HttpRequest
import io.micronaut.http.cookie.Cookies
import io.micronaut.inject.qualifiers.Qualifiers
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.testutils.ApplicationContextSpecification
import io.micronaut.security.oauth2.client.OpenIdProviderMetadata
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration
import io.micronaut.security.oauth2.endpoint.endsession.response.EndSessionCallbackUrlBuilder
import spock.lang.Shared

import javax.inject.Named
import javax.inject.Singleton

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

        when:
        def cookies = Stub(Cookies) {
            getAll() >> []
            findCookie(_) >> Optional.empty()
            values() >> []
            get(_, _) >> Optional.empty()
        }
        def httpParameters = Stub(HttpParameters) {
            getAll(_) >> []
            get(_) >> null
            names() >> []
            values() >> []
            get(_, _) >> Optional.empty()
        }
        def httpHeaders = Stub(HttpHeaders) {
            getAll(_) >> { args -> args[0] == 'Authorization' ? ['Bearer xxx.yyy.zzz'] : [] }
            get(_) >>  { args -> args[0] == 'Authorization' ? 'Bearer xxx.yyy.zzz' : null }
            names() >> ['Authorization']
            values() >> []
            findFirst(_) >> { args -> args[0] == 'Authorization' ? Optional.of('Bearer xxx.yyy.zzz') : Optional.empty() }
        }
        def authentication = Stub(Authentication) {
            getAttributes() >> [:]
        }
        def request = Stub(HttpRequest) {
            getCookies() >> cookies
            getParameters() >> httpParameters
            getHeaders() >> httpHeaders
            getUri() >> new URI("http://localhost:8080/")
        }
        String url = endSessionEndpoint.getUrl(request, authentication)

        then:
        url == 'https://dev-33333.oktapreview.com/oauth2/default/v1/logout?id_token_hint=xxx.yyy.zzz&post_logout_redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Flogout'
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
