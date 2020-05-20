package io.microanut.security.oauth2.docs.endpoint


import io.micronaut.context.annotation.Requires
import io.micronaut.core.async.publisher.Publishers
import io.micronaut.http.HttpStatus
import io.micronaut.http.client.DefaultHttpClientConfiguration
import io.micronaut.http.client.RxHttpClient
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.security.authentication.UserDetails
import io.micronaut.security.oauth2.endpoint.authorization.state.State
import io.micronaut.security.oauth2.endpoint.token.response.OauthUserDetailsMapper
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse
import io.reactivex.BackpressureStrategy
import io.reactivex.Flowable
import org.reactivestreams.Publisher

import javax.inject.Named
import javax.inject.Singleton
import io.micronaut.security.oauth2.docs.EmbeddedServerSpecification

class CsrfFilterSpec extends EmbeddedServerSpecification {

    @Override
    String getSpecName() {
        'CsrfFilterSpec'
    }

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                "oauth.csrf": true,
                'micronaut.security.login-handler': 'cookie',
                "micronaut.security.oauth2.clients.twitter.authorization.url": "https://twitter.com/authorize",
                "micronaut.security.oauth2.clients.twitter.token.url": "https://twitter.com/token",
                "micronaut.security.oauth2.clients.twitter.client-id": "myclient",
                "micronaut.security.oauth2.clients.twitter.client-secret": "mysecret",
        ]
    }

    void "test csrf filter"() {
        given:
        RxHttpClient client = applicationContext.createBean(RxHttpClient.class, embeddedServer.getURL(), new DefaultHttpClientConfiguration(followRedirects: false))

        when:
        client.toBlocking().exchange("/oauth/login/twitter")

        then:
        HttpClientResponseException ex = thrown()
        ex.status == HttpStatus.FORBIDDEN
    }


    @Singleton
    @Named("twitter")
    @Requires(property = "spec.name", value = "CsrfFilterSpec")
    static class TwitterUserDetailsMapper implements OauthUserDetailsMapper {

        @Override
        Publisher<UserDetails> createUserDetails(TokenResponse tokenResponse) {
            Publishers.just(new UnsupportedOperationException())
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
