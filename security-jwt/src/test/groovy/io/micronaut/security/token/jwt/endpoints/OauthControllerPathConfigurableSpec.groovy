package io.micronaut.security.token.jwt.endpoints

import io.micronaut.context.annotation.Requires
import io.micronaut.core.async.publisher.Publishers
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpStatus
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.security.authentication.UserDetails
import io.micronaut.security.token.event.RefreshTokenGeneratedEvent
import io.micronaut.security.token.refresh.RefreshTokenPersistence
import io.micronaut.testutils.EmbeddedServerSpecification
import org.reactivestreams.Publisher

import javax.inject.Singleton

class OauthControllerPathConfigurableSpec extends EmbeddedServerSpecification {

    @Override
    String getSpecName() {
        'OauthControllerPathConfigurableSpec'
    }

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
            'micronaut.security.endpoints.oauth.enabled': true,
            'micronaut.security.token.jwt.generator.refresh-token.secret': 'pleaseChangeThisSecretForANewOne',
            'micronaut.security.endpoints.oauth.path': '/newtoken',
        ]
    }

    void "OauthController is not accessible at /oauth/access_token but at /newtoken"() {
        given:
        TokenRefreshRequest creds = new TokenRefreshRequest('foo', 'XXXXXXXXXX')

        expect:
        applicationContext.getBean(OauthController.class)

        when:
        client.exchange(HttpRequest.POST('/oauth/access_token', creds))

        then:
        HttpClientResponseException e = thrown()
        e.status == HttpStatus.UNAUTHORIZED

        when:
        client.exchange(HttpRequest.POST('/newtoken', creds))

        then:
        e = thrown()
        e.status == HttpStatus.BAD_REQUEST
    }

    @Requires(property = 'spec.name', value = 'OauthControllerPathConfigurableSpec')
    @Singleton
    static class InMemoryRefreshTokenPersistence implements RefreshTokenPersistence {

        Map<String, UserDetails> tokens = [:]

        @Override
        void persistToken(RefreshTokenGeneratedEvent event) {
            tokens.put(event.getRefreshToken(), event.getUserDetails())
        }

        @Override
        Publisher<UserDetails> getUserDetails(String refreshToken) {
            Publishers.just(tokens.get(refreshToken))
        }
    }
}
