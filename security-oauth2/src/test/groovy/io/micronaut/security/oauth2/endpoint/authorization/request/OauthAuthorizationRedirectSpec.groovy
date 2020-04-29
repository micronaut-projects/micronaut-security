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
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.authentication.UserDetails
import io.micronaut.security.oauth2.OpenIDIntegrationSpec
import io.micronaut.security.oauth2.client.OauthClient
import io.micronaut.security.oauth2.endpoint.authorization.state.State
import io.micronaut.security.oauth2.endpoint.token.response.OauthUserDetailsMapper
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse
import io.micronaut.security.oauth2.routes.OauthController
import io.reactivex.Flowable
import org.reactivestreams.Publisher
import spock.lang.Specification
import spock.util.concurrent.PollingConditions

import javax.inject.Named
import javax.inject.Singleton
import java.nio.charset.StandardCharsets

class OauthAuthorizationRedirectSpec extends Specification {

    void "test authorization redirect with just oauth"() {
        given:
        Map config = new HashMap<>()
        config.put("spec.name", OauthAuthorizationRedirectSpec.simpleName)
        config.put("micronaut.security.token.jwt.cookie.enabled", true)
        config.put("micronaut.security.oauth2.clients.twitter.authorization.url", "https://twitter.com/authorize")
        config.put("micronaut.security.oauth2.clients.twitter.token.url", "https://twitter.com/token")
        config.put("micronaut.security.oauth2.clients.twitter.client-id", "myclient")
        config.put("micronaut.security.oauth2.clients.twitter.client-secret", "mysecret")
        EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer, config)
        ApplicationContext context = embeddedServer.getApplicationContext()
        RxHttpClient client = context.createBean(RxHttpClient.class, embeddedServer.getURL(), new DefaultHttpClientConfiguration(followRedirects: false))
        PollingConditions conditions = new PollingConditions(timeout: 10)
        conditions.eventually {
            assert embeddedServer.isRunning()
        }

        expect:
        context.findBean(OauthClient, Qualifiers.byName("twitter")).isPresent()
        context.findBean(OauthController, Qualifiers.byName("twitter")).isPresent()

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
        String parsedLocation = OpenIdAuthorizationRedirectSpec.stateParser(location)

        then:
        parsedLocation.contains('"nonce":"')
        parsedLocation.contains('"redirectUri":"http://localhost:'+ embeddedServer.getPort() + '/oauth/callback/twitter"')

        cleanup:
        context.close()
    }

    void "test csrf filter"() {
        given:
        Map config = new HashMap<>()
        config.put("spec.name", "OauthAuthorizationRedirectSpec")
        config.put("micronaut.security.token.jwt.cookie.enabled", true)
        config.put("micronaut.security.oauth2.clients.twitter.authorization.url", "https://twitter.com/authorize")
        config.put("micronaut.security.oauth2.clients.twitter.token.url", "https://twitter.com/token")
        config.put("micronaut.security.oauth2.clients.twitter.client-id", "myclient")
        config.put("micronaut.security.oauth2.clients.twitter.client-secret", "mysecret")
        EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer, config)
        ApplicationContext context = embeddedServer.getApplicationContext()
        RxHttpClient client = context.createBean(RxHttpClient.class, embeddedServer.getURL(), new DefaultHttpClientConfiguration(followRedirects: false))
        PollingConditions conditions = new PollingConditions(timeout: 10)
        conditions.eventually {
            assert embeddedServer.isRunning()
        }

        when:
        client.toBlocking().exchange("/oauth/login/twitter")

        then:
        def ex = thrown(HttpClientResponseException)
        ex.status == HttpStatus.FORBIDDEN
    }

    @Singleton
    @Named("twitter")
    @Requires(property = "spec.name", value = "OauthAuthorizationRedirectSpec")
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
