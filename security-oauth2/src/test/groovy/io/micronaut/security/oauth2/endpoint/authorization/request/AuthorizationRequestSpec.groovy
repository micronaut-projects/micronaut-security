package io.micronaut.security.oauth2.endpoint.authorization.request

import io.micronaut.http.MutableHttpResponse
import spock.lang.Specification

class AuthorizationRequestSpec extends Specification {

    void "AuthorizationRequest::getPkceChallenge(MutableHttpResponse) defaults to Optional.empty()"() {
        when:
        AuthorizationRequest authorizationRequest = new AuthorizationRequest() {
            @Override
            List<String> getScopes() {
                return null
            }
            @Override
            String getClientId() {
                return null
            }
            @Override
            Optional<String> getState(MutableHttpResponse<?> response) {
                return null
            }
            @Override
            String getResponseType() {
                return null
            }
            @Override
            Optional<String> getRedirectUri() {
                return null
            }
        }

        then:
        authorizationRequest.getPkceChallenge(null) != null
        !authorizationRequest.getPkceChallenge(null).isPresent()

        and:
        authorizationRequest.clientId == null
    }
}
