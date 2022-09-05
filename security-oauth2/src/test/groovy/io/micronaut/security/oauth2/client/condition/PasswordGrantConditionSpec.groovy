package io.micronaut.security.oauth2.client.condition

import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Requires
import io.micronaut.security.authentication.AuthenticationProvider
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.oauth2.endpoint.authorization.state.State
import io.micronaut.security.oauth2.endpoint.token.response.OauthAuthenticationMapper
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse
import jakarta.inject.Named
import jakarta.inject.Singleton
import org.reactivestreams.Publisher
import reactor.core.publisher.FluxSink
import spock.lang.Specification
import reactor.core.publisher.Flux

import javax.annotation.Nullable

class PasswordGrantConditionSpec extends Specification{

    void "PasswordGrantCondition evaluates to true for openId grant-type=password configuration"(){
        given:
        ApplicationContext ctx = ApplicationContext.run(['micronaut.security.oauth2.clients.foo.grant-type': 'password',
                                                         'micronaut.security.oauth2.clients.foo.client-id': 'clientId',
                                                         'micronaut.security.oauth2.clients.foo.client-secret': 'clientSecret',
                                                         'micronaut.security.oauth2.clients.foo.openid.token': 'https:/foo.com/auth/token'])

        when:
        ctx.getBean(AuthenticationProvider)

        then:
        noExceptionThrown()

        cleanup:
        ctx.close()
    }

    void "PasswordGrantCondition to true for oauth2 grant-type=password configuration"(){
        given:
        ApplicationContext ctx = ApplicationContext.run(['micronaut.security.oauth2.clients.foo.grant-type': 'password',
                                                         'micronaut.security.oauth2.clients.foo.client-id': 'clientId',
                                                         'micronaut.security.oauth2.clients.foo.client-secret': 'clientSecret',
                                                         'micronaut.security.oauth2.clients.foo.token.url': 'https://foo.com/auth/token',
                                                         'spec.name'                                            : 'FooNamedPasswordAuthenticationProviderSpec'])

        when:
        ctx.getBean(AuthenticationProvider)

        then:
        noExceptionThrown()

        cleanup:
        ctx.close()
    }

    @Singleton
    @Named("foo")
    @Requires(property = "spec.name", value = "FooNamedPasswordAuthenticationProviderSpec")
    static class FooAuthenticationMapper implements OauthAuthenticationMapper{

        @Override
        Publisher<AuthenticationResponse> createAuthenticationResponse(TokenResponse tokenResponse, @Nullable State state) {
            Flux.create({emitter ->
                emitter.next(AuthenticationResponse.success("fooUser"))
                emitter.complete()
            },  FluxSink.OverflowStrategy.ERROR)
        }
    }
}
