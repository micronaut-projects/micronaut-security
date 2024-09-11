package io.micronaut.security.oauth2.client.condition

import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Requires
import io.micronaut.core.annotation.Nullable
import io.micronaut.json.JsonMapper
import io.micronaut.json.tree.JsonNode
import io.micronaut.security.authentication.AuthenticationRequest
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.authentication.provider.ReactiveAuthenticationProvider
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration
import io.micronaut.security.oauth2.endpoint.authorization.state.State
import io.micronaut.security.oauth2.endpoint.token.response.OauthAuthenticationMapper
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse
import io.micronaut.security.oauth2.grants.PasswordGrant
import jakarta.inject.Named
import jakarta.inject.Singleton
import org.reactivestreams.Publisher
import reactor.core.publisher.Flux
import reactor.core.publisher.FluxSink
import spock.lang.Specification
import spock.lang.Unroll

class PasswordGrantConditionSpec extends Specification {

    private static Map<String, String> PROPS = [
            'micronaut.security.oauth2.clients.foo.grant-type': 'password',
            'micronaut.security.oauth2.clients.foo.client-id': 'clientId',
            'micronaut.security.oauth2.clients.foo.client-secret': 'clientSecret'
    ]

    void snakeCaseStrategyIsUsed() {
        given:
        JsonMapper jsonMapper = JsonMapper.createDefault()

        AuthenticationRequest authenticationRequest = Stub(AuthenticationRequest) {
            getIdentity() >> "username"
            getSecret() >> "password"
        }
        OauthClientConfiguration oauthClientConfiguration = Stub(OauthClientConfiguration) {
            getScopes() >> ['scope']
        }
        PasswordGrant obj = new PasswordGrant(authenticationRequest, oauthClientConfiguration)
        obj.scope = "scope"

        when:
        JsonNode jsonNode = jsonMapper.writeValueToTree(obj)
        then:
        jsonNode.isObject()
        4 == jsonNode.size()
        "scope" == jsonNode.get("scope").getStringValue()
        "password" == jsonNode.get("password").getStringValue()
        "password" == jsonNode.get("grant_type").getStringValue()
        "username" == jsonNode.get("username").getStringValue()
    }

    @Unroll("#description")
    void "evaluate PasswordGrantCondition"(Map<String, String> properties,
                                           String description) {
        given:
        ApplicationContext ctx = ApplicationContext.run(PROPS + properties)

        expect:
        ctx.containsBean(ReactiveAuthenticationProvider)

        when:
        ctx.getBean(ReactiveAuthenticationProvider)

        then:
        noExceptionThrown()

        cleanup:
        ctx.close()

        where:
        properties | description
        ['micronaut.security.oauth2.clients.foo.openid.token.url': 'https:/foo.com/auth/token'] | "PasswordGrantCondition evaluates to true for openId grant-type=password configuration"
        ['micronaut.security.oauth2.clients.foo.token.url': 'https://foo.com/auth/token', 'spec.name': 'FooNamedPasswordAuthenticationProviderSpec'] | "PasswordGrantCondition to true for oauth2 grant-type=password configuration"
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
