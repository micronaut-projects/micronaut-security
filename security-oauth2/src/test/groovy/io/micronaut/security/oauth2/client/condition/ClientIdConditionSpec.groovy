package io.micronaut.security.oauth2.client.condition

import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Requires
import io.micronaut.context.exceptions.NoSuchBeanException
import io.micronaut.inject.qualifiers.Qualifiers
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.oauth2.client.OauthClient
import io.micronaut.security.oauth2.client.OpenIdClient
import io.micronaut.security.oauth2.client.clientcredentials.ClientCredentialsClient
import io.micronaut.security.oauth2.endpoint.authorization.state.State
import io.micronaut.security.oauth2.endpoint.token.response.OauthAuthenticationMapper
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse
import jakarta.inject.Named
import jakarta.inject.Singleton
import org.jspecify.annotations.Nullable
import org.reactivestreams.Publisher
import reactor.core.publisher.Mono
import spock.lang.Specification

class ClientIdConditionSpec extends Specification {

    private static final String SPEC_NAME = 'ClientIdConditionSpec'

    void "OpenID client without client-id is not created and the failure names the client-id property"() {
        given:
        ApplicationContext ctx = ApplicationContext.run([
                'spec.name': SPEC_NAME,
                'micronaut.security.oauth2.clients.foo.openid.authorization.url': 'https://appleid.apple.com/auth/authorize',
                'micronaut.security.oauth2.clients.foo.openid.token.url': 'https://appleid.apple.com/auth/token',
        ])

        when:
        ctx.getBean(OpenIdClient, Qualifiers.byName('foo'))

        then:
        NoSuchBeanException e = thrown()
        e.message.contains('micronaut.security.oauth2.clients.foo.client-id')

        and:
        !ctx.findBean(ClientCredentialsClient, Qualifiers.byName('foo')).isPresent()

        cleanup:
        ctx.close()
    }

    void "OAuth 2.0 client without client-id is not created and the failure names the client-id property"() {
        given:
        ApplicationContext ctx = ApplicationContext.run([
                'spec.name': SPEC_NAME,
                'micronaut.security.oauth2.clients.bar.authorization.url': 'https://example.com/authorize',
                'micronaut.security.oauth2.clients.bar.token.url': 'https://example.com/token',
        ])

        when:
        ctx.getBean(OauthClient, Qualifiers.byName('bar'))

        then:
        NoSuchBeanException e = thrown()
        e.message.contains('micronaut.security.oauth2.clients.bar.client-id')

        when:
        ctx.getBean(ClientCredentialsClient, Qualifiers.byName('bar'))

        then:
        NoSuchBeanException ex = thrown()
        ex.message.contains('micronaut.security.oauth2.clients.bar.client-id')

        cleanup:
        ctx.close()
    }

    void "fully configured clients are created"() {
        given:
        ApplicationContext ctx = ApplicationContext.run([
                'spec.name': SPEC_NAME,
                'micronaut.security.oauth2.clients.foo.client-id': 'XXXX',
                'micronaut.security.oauth2.clients.foo.client-secret': 'YYYY',
                'micronaut.security.oauth2.clients.foo.openid.authorization.url': 'https://appleid.apple.com/auth/authorize',
                'micronaut.security.oauth2.clients.foo.openid.token.url': 'https://appleid.apple.com/auth/token',
                'micronaut.security.oauth2.clients.bar.client-id': 'XXXX',
                'micronaut.security.oauth2.clients.bar.client-secret': 'YYYY',
                'micronaut.security.oauth2.clients.bar.authorization.url': 'https://example.com/authorize',
                'micronaut.security.oauth2.clients.bar.token.url': 'https://example.com/token',
        ])

        expect:
        ctx.findBean(OpenIdClient, Qualifiers.byName('foo')).isPresent()
        ctx.findBean(ClientCredentialsClient, Qualifiers.byName('foo')).isPresent()
        ctx.findBean(OauthClient, Qualifiers.byName('bar')).isPresent()
        ctx.findBean(ClientCredentialsClient, Qualifiers.byName('bar')).isPresent()

        cleanup:
        ctx.close()
    }

    @Requires(property = 'spec.name', value = SPEC_NAME)
    @Singleton
    @Named('bar')
    static class BarAuthenticationMapper implements OauthAuthenticationMapper {
        @Override
        Publisher<AuthenticationResponse> createAuthenticationResponse(TokenResponse tokenResponse, @Nullable State state) {
            Mono.just(AuthenticationResponse.success('john'))
        }
    }
}
