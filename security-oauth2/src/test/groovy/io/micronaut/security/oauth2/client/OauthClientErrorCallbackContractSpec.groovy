package io.micronaut.security.oauth2.client

import io.micronaut.context.BeanContext
import io.micronaut.http.HttpRequest
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration
import io.micronaut.security.oauth2.endpoint.authorization.request.AuthorizationRedirectHandler
import io.micronaut.security.oauth2.endpoint.authorization.response.AuthorizationErrorResponse
import io.micronaut.security.oauth2.endpoint.authorization.response.AuthorizationErrorResponseException
import io.micronaut.security.oauth2.endpoint.authorization.response.OauthAuthorizationResponseHandler
import io.micronaut.security.oauth2.endpoint.authorization.response.OpenIdAuthorizationResponseHandler
import io.micronaut.security.oauth2.endpoint.authorization.state.State
import io.micronaut.security.oauth2.endpoint.authorization.state.validation.StateValidator
import io.micronaut.security.oauth2.endpoint.token.response.OauthAuthenticationMapper
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdAuthenticationMapper
import org.reactivestreams.Publisher
import reactor.core.publisher.Flux
import spock.lang.Specification

import java.util.function.Supplier

/**
 * Both {@link DefaultOauthClient} and {@link DefaultOpenIdClient} implement {@link OauthClient}, so an error callback
 * must be signalled the same way by both: through the returned publisher rather than by throwing from onCallback.
 */
class OauthClientErrorCallbackContractSpec extends Specification {

    void "#clientType signals an error callback through the returned publisher (state validator: #withStateValidator)"(String clientType, boolean withStateValidator) {
        given:
        State state = Stub(State)
        AuthorizationErrorResponse errorResponse = Stub(AuthorizationErrorResponse) {
            getState() >> state
        }
        BeanContext beanContext = Stub(BeanContext) {
            createBean(AuthorizationErrorResponse, _) >> errorResponse
        }
        StateValidator stateValidatorMock = Mock(StateValidator)
        OauthClient oauthClient = createClient(clientType, beanContext, withStateValidator ? stateValidatorMock : null)
        HttpRequest<Map<String, Object>> request = HttpRequest.GET('/oauth/callback/auth?error=access_denied&state=xyz')

        when: 'onCallback is invoked'
        Publisher<AuthenticationResponse> publisher = oauthClient.onCallback(request)

        then: 'it does not throw and the state is validated when a validator is present'
        noExceptionThrown()
        publisher != null
        (withStateValidator ? 1 : 0) * stateValidatorMock.validate(request, state)

        when: 'the returned publisher is subscribed to'
        List<Throwable> errors = []
        List<AuthenticationResponse> responses = Flux.from(publisher)
                .onErrorResume { Throwable t ->
                    errors << t
                    Flux.empty()
                }
                .collectList()
                .block()

        then: 'the error is emitted as an AuthorizationErrorResponseException'
        responses.isEmpty()
        errors.size() == 1
        errors[0] instanceof AuthorizationErrorResponseException
        ((AuthorizationErrorResponseException) errors[0]).authorizationErrorResponse.is(errorResponse)

        where:
        clientType            | withStateValidator
        'DefaultOauthClient'  | true
        'DefaultOauthClient'  | false
        'DefaultOpenIdClient' | true
        'DefaultOpenIdClient' | false
    }

    private OauthClient createClient(String clientType, BeanContext beanContext, StateValidator stateValidator) {
        OauthClientConfiguration configuration = Stub(OauthClientConfiguration) {
            getName() >> 'auth'
        }
        if (clientType == 'DefaultOauthClient') {
            return new DefaultOauthClient(Stub(OauthAuthenticationMapper),
                    configuration,
                    Stub(AuthorizationRedirectHandler),
                    Stub(OauthAuthorizationResponseHandler),
                    beanContext,
                    stateValidator)
        }
        Supplier<OpenIdProviderMetadata> metadata = { -> Stub(OpenIdProviderMetadata) } as Supplier<OpenIdProviderMetadata>
        new DefaultOpenIdClient(configuration,
                metadata,
                Stub(OpenIdAuthenticationMapper),
                Stub(AuthorizationRedirectHandler),
                Stub(OpenIdAuthorizationResponseHandler),
                beanContext,
                null,
                stateValidator)
    }
}
