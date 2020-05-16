package io.micronaut.security.oauth2.endpoint.authorization.request

import io.micronaut.context.annotation.Requires
import io.micronaut.core.async.publisher.Publishers
import io.micronaut.http.HttpHeaders
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.client.DefaultHttpClientConfiguration
import io.micronaut.http.client.RxHttpClient
import io.micronaut.inject.qualifiers.Qualifiers
import io.micronaut.security.authentication.UserDetails
import io.micronaut.security.oauth2.EmbeddedServerSpecification
import io.micronaut.security.oauth2.Keycloak
import io.micronaut.security.oauth2.StateUtils
import io.micronaut.security.oauth2.client.OauthClient
import io.micronaut.security.oauth2.client.OpenIdClient
import io.micronaut.security.oauth2.endpoint.authorization.state.State
import io.micronaut.security.oauth2.endpoint.token.response.OauthUserDetailsMapper
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse
import io.micronaut.security.oauth2.routes.OauthController
import io.reactivex.Flowable
import org.reactivestreams.Publisher

import javax.inject.Named
import javax.inject.Singleton
import java.nio.charset.StandardCharsets

class OpenIdAuthorizationRedirectSpec extends EmbeddedServerSpecification {

    @Override
    String getSpecName() {
        'OpenIdAuthorizationRedirectSpec'
    }

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                "micronaut.security.token.jwt.cookie.enabled"                : true,
                "micronaut.security.oauth2.clients.keycloak.openid.issuer"   : Keycloak.issuer,
                "micronaut.security.oauth2.clients.keycloak.client-id"       : Keycloak.CLIENT_ID,
                "micronaut.security.oauth2.clients.keycloak.client-secret"   : Keycloak.clientSecret,
                "micronaut.security.oauth2.clients.twitter.authorization.url": "https://twitter.com/authorize",
                "micronaut.security.oauth2.clients.twitter.token.url"        : "https://twitter.com/token",
                "micronaut.security.oauth2.clients.twitter.client-id"        : Keycloak.CLIENT_ID,
                "micronaut.security.oauth2.clients.twitter.client-secret"    : "mysecret",
        ]
    }

    void "test authorization redirect for openid and normal oauth"() {
        given:
        RxHttpClient client = applicationContext.createBean(RxHttpClient.class, embeddedServer.getURL(), new DefaultHttpClientConfiguration(followRedirects: false))

        expect:
        applicationContext.findBean(OpenIdClient, Qualifiers.byName("keycloak")).isPresent()
        applicationContext.findBean(OauthClient, Qualifiers.byName("twitter")).isPresent()
        applicationContext.findBean(OauthController, Qualifiers.byName("keycloak")).isPresent()
        applicationContext.findBean(OauthController, Qualifiers.byName("twitter")).isPresent()

        when:
        HttpResponse response = client.toBlocking().exchange("/oauth/login/keycloak")

        then:
        noExceptionThrown()
        response.status == HttpStatus.FOUND

        when:
        String location = URLDecoder.decode(response.header(HttpHeaders.LOCATION), StandardCharsets.UTF_8.toString())

        then:
        location.startsWith(Keycloak.issuer + "/protocol/openid-connect/auth")
        location.contains("scope=openid email profile")
        location.contains("response_type=code")
        location.contains("redirect_uri=http://localhost:" + embeddedServer.getPort() + "/oauth/callback/keycloak")
        String parsedLocation = StateUtils.stateParser(location)
        parsedLocation.contains('"nonce":"')
        parsedLocation.contains('"redirectUri":"http://localhost:'+ embeddedServer.getPort() + '/oauth/callback/keycloak"')
        location.contains("client_id=$Keycloak.CLIENT_ID")

        when:
        response = client.toBlocking().exchange("/oauth/login/twitter")
        location = URLDecoder.decode(response.header(HttpHeaders.LOCATION), StandardCharsets.UTF_8.toString())
        parsedLocation = StateUtils.stateParser(location)

        then:
        response.status == HttpStatus.FOUND
        location.startsWith("https://twitter.com/authorize")
        !location.contains("scope=")
        location.contains("response_type=code")
        location.contains("redirect_uri=http://localhost:" + embeddedServer.getPort() + "/oauth/callback/twitter")
        parsedLocation.contains('"nonce":"')
        parsedLocation.contains('"redirectUri":"http://localhost:'+ embeddedServer.getPort() + '/oauth/callback/twitter"')
        location.contains("client_id=$Keycloak.CLIENT_ID")
    }

    @Singleton
    @Named("twitter")
    @Requires(property = "spec.name", value = "OpenIdAuthorizationRedirectSpec")
    @Requires(property = "micronaut.security.oauth2.clients.twitter")
    static class TwitterUserDetailsMapper implements OauthUserDetailsMapper {

        @Override
        Publisher<UserDetails> createUserDetails(TokenResponse tokenResponse) {
            return Publishers.just(new UnsupportedOperationException())
        }

        @Override
        Publisher<UserDetails> createAuthenticationResponse(TokenResponse tokenResponse, State state) {
            return Flowable.just(new UserDetails("twitterUser", Collections.emptyList()))
        }
    }
}
