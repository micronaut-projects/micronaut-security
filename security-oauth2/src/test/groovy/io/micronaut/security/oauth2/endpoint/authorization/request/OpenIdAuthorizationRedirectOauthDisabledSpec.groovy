package io.micronaut.security.oauth2.endpoint.authorization.request

import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Requires
import io.micronaut.core.async.publisher.Publishers
import io.micronaut.http.HttpHeaders
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.client.DefaultHttpClientConfiguration
import io.micronaut.http.client.RxHttpClient
import io.micronaut.http.client.exceptions.HttpClientResponseException
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
import io.reactivex.BackpressureStrategy
import io.reactivex.Flowable
import org.reactivestreams.Publisher
import spock.lang.IgnoreIf

import javax.inject.Named
import javax.inject.Singleton
import java.nio.charset.StandardCharsets

@IgnoreIf({ sys['testcontainers'] == false })
class OpenIdAuthorizationRedirectOauthDisabledSpec extends EmbeddedServerSpecification {

    @Override
    String getSpecName() {
        'OpenIdAuthorizationRedirectOauthDisabledSpec'
    }

    @Override
    Map<String, Object> getConfiguration() {
        Keycloak.init()
        super.configuration + [
                'micronaut.security.authentication': 'cookie',
                "micronaut.security.oauth2.clients.keycloak.openid.issuer": Keycloak.issuer,
                "micronaut.security.oauth2.clients.keycloak.client-id": Keycloak.CLIENT_ID,
                "micronaut.security.oauth2.clients.keycloak.client-secret": Keycloak.clientSecret,
                "micronaut.security.oauth2.clients.twitter.authorization.url": "https://twitter.com/authorize",
                "micronaut.security.oauth2.clients.twitter.token.url": "https://twitter.com/token",
                "micronaut.security.oauth2.clients.twitter.client-id": Keycloak.CLIENT_ID,
                "micronaut.security.oauth2.clients.twitter.client-secret": "mysecret",
                "micronaut.security.oauth2.clients.twitter.enabled": false,
        ]
    }

    void "test authorization redirect with openid and oauth disabled"() {
        given:
        RxHttpClient client = applicationContext.createBean(RxHttpClient.class, embeddedServer.getURL(), new DefaultHttpClientConfiguration(followRedirects: false))

        expect:
        applicationContext.findBean(OpenIdClient, Qualifiers.byName("keycloak")).isPresent()
        !applicationContext.findBean(OauthClient, Qualifiers.byName("twitter")).isPresent()
        applicationContext.findBean(OauthController, Qualifiers.byName("keycloak")).isPresent()
        !applicationContext.findBean(OauthController, Qualifiers.byName("twitter")).isPresent()

        when:
        HttpResponse response = client.toBlocking().exchange("/oauth/login/keycloak")
        String location = URLDecoder.decode(response.header(HttpHeaders.LOCATION), StandardCharsets.UTF_8.toString())

        then:
        response.status == HttpStatus.FOUND
        location.startsWith(Keycloak.issuer + "/protocol/openid-connect/auth")
        location.contains("scope=openid email profile")
        location.contains("response_type=code")
        location.contains("redirect_uri=http://localhost:" + embeddedServer.getPort() + "/oauth/callback/keycloak")
        String parsedLocation = StateUtils.stateParser(location)
        parsedLocation.contains('"nonce":"')
        parsedLocation.contains('"redirectUri":"http://localhost:'+ embeddedServer.getPort() + '/oauth/callback/keycloak"')
        location.contains("client_id=$Keycloak.CLIENT_ID")

        when:
        client.toBlocking().exchange("/oauth/login/twitter")

        then:
        def ex = thrown(HttpClientResponseException)
        ex.response.status.code == 401
    }

    @Singleton
    @Named("twitter")
    @Requires(property = "spec.name", value = "OpenIdAuthorizationRedirectOauthDisabledSpec")
    @Requires(property = "micronaut.security.oauth2.clients.twitter")
    static class TwitterUserDetailsMapper implements OauthUserDetailsMapper {

        @Override
        Publisher<UserDetails> createUserDetails(TokenResponse tokenResponse) {
            return Publishers.just(new UnsupportedOperationException())
        }

        @Override
        Publisher<UserDetails> createAuthenticationResponse(TokenResponse tokenResponse, State state) {
            Flowable.create({ emitter ->
                emitter.onNext(new UserDetails("twitterUser", Collections.emptyList()))
                emitter.onComplete()
            }, BackpressureStrategy.ERROR)
        }
    }
}
