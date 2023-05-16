package io.micronaut.security.oauth2.endpoint.authorization.request

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
}
