package io.micronaut.security.oauth2.endpoint.authorization.request

import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpHeaders
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.client.DefaultHttpClientConfiguration
import io.micronaut.http.client.HttpClient
import io.micronaut.inject.qualifiers.Qualifiers
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.oauth2.PKCEUtils
import io.micronaut.security.oauth2.StateUtils
import io.micronaut.security.oauth2.client.OauthClient
import io.micronaut.security.oauth2.endpoint.authorization.pkce.S256PkceGenerator
import io.micronaut.security.oauth2.endpoint.authorization.state.State
import io.micronaut.security.oauth2.endpoint.token.response.OauthAuthenticationMapper
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse
import io.micronaut.security.oauth2.routes.OauthController
import io.micronaut.security.testutils.EmbeddedServerSpecification
import jakarta.inject.Named
import jakarta.inject.Singleton
import org.reactivestreams.Publisher
import reactor.core.publisher.Flux
import reactor.core.publisher.FluxSink

import java.nio.charset.StandardCharsets
import java.util.regex.Pattern

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
                "micronaut.security.oauth2.pkce.cookie.cookie-name" :"OAUTH2_PKCE",
                "micronaut.security.oauth2.pkce.cookie.cookie-path" :"/",
                "micronaut.security.oauth2.pkce.cookie.cookie-http-only" :"true",
                "micronaut.security.oauth2.pkce.cookie.cookie-max-age" :"5m",
        ]
    }

    void "test authorization redirect with just oauth"() {
        given:
        Pattern VALID_CODE_CHALLENGE_PATTERN = Pattern.compile('^[0-9a-zA-Z\\-\\.~_]+$')
        HttpClient client = applicationContext.createBean(HttpClient.class, embeddedServer.getURL(), new DefaultHttpClientConfiguration(followRedirects: false))

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
        !response.getCookie("OAUTH2_PKCE").isPresent()

        when:
        Map<String, String> queryValues = StateUtils.queryValuesAsMap(location)
        String state = StateUtils.decodeState(queryValues)

        then:
        state.contains('"nonce":"')
        state.contains('"redirectUri":"http://localhost:' + embeddedServer.getPort() + '/oauth/callback/twitter"')

        when:
        String codeChallenge = PKCEUtils.getCodeChallenge(queryValues)
        String codeChallengeMethod = PKCEUtils.getCodeChallengeMethod(queryValues)

        then:
        !codeChallenge
        !codeChallengeMethod
    }

    @Singleton
    @Named("twitter")
    @Requires(property = "spec.name", value = "OauthAuthorizationRedirectSpec")
    static class TwitterAuthenticationMapper implements OauthAuthenticationMapper {

        @Override
        Publisher<Authentication> createAuthenticationResponse(TokenResponse tokenResponse, State state) {
            Flux.create({ emitter ->
                emitter.next(Authentication.build("twitterUser"))
                emitter.complete()
            }, FluxSink.OverflowStrategy.ERROR)
        }
    }
}
