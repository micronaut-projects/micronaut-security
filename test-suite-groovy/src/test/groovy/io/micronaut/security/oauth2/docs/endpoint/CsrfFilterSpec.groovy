package io.micronaut.security.oauth2.docs.endpoint

import io.micronaut.context.annotation.Requires
import io.micronaut.core.annotation.Nullable
import io.micronaut.http.HttpStatus
import io.micronaut.http.client.DefaultHttpClientConfiguration
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.oauth2.endpoint.authorization.state.State
import io.micronaut.security.oauth2.endpoint.token.response.OauthAuthenticationMapper
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse
import io.micronaut.security.testutils.EmbeddedServerSpecification
import jakarta.inject.Named
import jakarta.inject.Singleton
import org.reactivestreams.Publisher
import reactor.core.publisher.Flux
import reactor.core.publisher.FluxSink

class CsrfFilterSpec extends EmbeddedServerSpecification {

    @Override
    String getSpecName() {
        'CsrfFilterSpec'
    }

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                "oauth.csrf": true,
                'micronaut.security.authentication': 'cookie',
                "micronaut.security.oauth2.clients.twitter.authorization.url": "https://twitter.com/authorize",
                "micronaut.security.oauth2.clients.twitter.token.url": "https://twitter.com/token",
                "micronaut.security.oauth2.clients.twitter.client-id": "myclient",
                "micronaut.security.oauth2.clients.twitter.client-secret": "mysecret",
        ]
    }

    void "test csrf filter"() {
        given:
        HttpClient client = applicationContext.createBean(HttpClient.class, embeddedServer.getURL(), new DefaultHttpClientConfiguration(followRedirects: false))

        when:
        client.toBlocking().exchange("/oauth/login/twitter")

        then:
        HttpClientResponseException ex = thrown()
        ex.status == HttpStatus.FORBIDDEN
    }

    @Singleton
    @Named("twitter")
    @Requires(property = "spec.name", value = "CsrfFilterSpec")
    static class TwitterAuthenticationMapper implements OauthAuthenticationMapper {

        @Override
        Publisher<AuthenticationResponse> createAuthenticationResponse(TokenResponse tokenResponse, @Nullable State state) {
            Flux.create({ emitter ->
                emitter.next(AuthenticationResponse.success("twitterUser"))
                emitter.complete()
            }, FluxSink.OverflowStrategy.ERROR)
        }
    }
}
