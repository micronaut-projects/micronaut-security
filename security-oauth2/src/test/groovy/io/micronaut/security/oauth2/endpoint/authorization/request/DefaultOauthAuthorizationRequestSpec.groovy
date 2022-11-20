package io.micronaut.security.oauth2.endpoint.authorization.request

import io.micronaut.http.HttpRequest
import io.micronaut.http.MutableHttpResponse
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration
import io.micronaut.security.oauth2.configuration.endpoints.OauthAuthorizationEndpointConfiguration
import spock.lang.Specification

class DefaultOauthAuthorizationRequestSpec extends Specification {
    void "If PkceFactory is null challenge is null, getPkceChallenge return empty optional"() {
        given:
        def oauthAuthorizationEndpointConfiguration = Stub(OauthAuthorizationEndpointConfiguration) {
            getCodeChallengeMethod() >> Optional.of('S256')
        }
        def oauthClientConfiguration = Stub(OauthClientConfiguration) {
            getAuthorization() >> Optional.of(oauthAuthorizationEndpointConfiguration)
        }
        expect:
        !new DefaultOauthAuthorizationRequest(null, oauthClientConfiguration, null, null, null).getPkceChallenge(null).isPresent()
    }

    void "Use deprecated constructor"() {
        given:
        def request = Mock(HttpRequest)
        def response = Mock(MutableHttpResponse)
        def oauthAuthorizationEndpointConfiguration = Mock(OauthAuthorizationEndpointConfiguration) {
            getCodeChallengeMethod() >> Optional.of('plain')
        }
        def oauthClientConfiguration = Stub(OauthClientConfiguration) {
            getAuthorization() >> Optional.of(oauthAuthorizationEndpointConfiguration)
        }
        expect:
        new DefaultOauthAuthorizationRequest(request, oauthClientConfiguration, null, null).getPkceChallenge(response).isPresent()
        'plain' == new DefaultOauthAuthorizationRequest(request, oauthClientConfiguration, null, null).getPkceChallenge(response).get().codeChallengeMethod
    }
}
