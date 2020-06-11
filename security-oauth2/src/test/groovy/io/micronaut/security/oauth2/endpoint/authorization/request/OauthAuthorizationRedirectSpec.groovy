package io.micronaut.security.oauth2.endpoint.authorization.request

import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpHeaders
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.client.DefaultHttpClientConfiguration
import io.micronaut.http.client.RxHttpClient
import io.micronaut.inject.qualifiers.Qualifiers
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.oauth2.EmbeddedServerSpecification
import io.micronaut.security.oauth2.StateUtils
import io.micronaut.security.oauth2.client.OauthClient
import io.micronaut.security.oauth2.endpoint.authorization.state.State
import io.micronaut.security.oauth2.endpoint.token.response.OauthAuthenticationMapper
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse
import io.micronaut.security.oauth2.routes.OauthController
import io.micronaut.security.token.config.TokenConfiguration
import io.reactivex.BackpressureStrategy
import io.reactivex.Flowable
import org.reactivestreams.Publisher

import javax.inject.Named
import javax.inject.Singleton
import java.nio.charset.StandardCharsets

class OauthAuthorizationRedirectSpec extends EmbeddedServerSpecification {

    @Override
    String getSpecName() {
        'OauthAuthorizationRedirectSpec'
    }

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.authentication': 'cookie',
                "micronaut.security.oauth2.clients.twitter.authorization.url": "https://twitter.com/authorize",
                "micronaut.security.oauth2.clients.twitter.token.url": "https://twitter.com/token",
                "micronaut.security.oauth2.clients.twitter.client-id": "myclient",
                "micronaut.security.oauth2.clients.twitter.client-secret": "mysecret",
        ]
    }

    void "test authorization redirect with just oauth"() {
        given:
        RxHttpClient client = applicationContext.createBean(RxHttpClient.class, embeddedServer.getURL(), new DefaultHttpClientConfiguration(followRedirects: false))

        expect:
        applicationContext.findBean(OauthClient, Qualifiers.byName("twitter")).isPresent()
        applicationContext.findBean(OauthController, Qualifiers.byName("twitter")).isPresent()

        when:
        HttpResponse response = client.toBlocking().exchange("/oauth/login/twitter")
        String location = URLDecoder.decode(response.header(HttpHeaders.LOCATION), StandardCharsets.UTF_8.toString())

        then:
        response.status == HttpStatus.FOUND
        location.startsWith("https://twitter.com/authorize")
        !location.contains("scope=")
        location.contains("response_type=code")
        location.contains("redirect_uri=http://localhost:" + embeddedServer.getPort() + "/oauth/callback/twitter")
        location.contains("client_id=myclient")

        when:
        String parsedLocation = StateUtils.stateParser(location)

        then:
        parsedLocation.contains('"nonce":"')
        parsedLocation.contains('"redirectUri":"http://localhost:'+ embeddedServer.getPort() + '/oauth/callback/twitter"')
    }

    @Singleton
    @Named("twitter")
    @Requires(property = "spec.name", value = "OauthAuthorizationRedirectSpec")
    static class TwitterAuthenticationMapper implements OauthAuthenticationMapper {
        @Override
        Publisher<Authentication> createAuthenticationResponse(TokenResponse tokenResponse, State state) {
            Flowable.create({ emitter ->
                emitter.onNext(AuthenticationResponse.build('twitterUser', new TokenConfiguration() {}))
                emitter.onComplete()
            }, BackpressureStrategy.ERROR)
        }
    }
}
