package io.micronaut.security.oauth2.endpoint

import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.oauth2.handlers.SuccessfulIdTokenAccessTokenResponseHandler
import io.micronaut.security.oauth2.endpoints.token.response.OpenIdTokenResponse
import io.micronaut.security.oauth2.endpoints.authorization.response.AuthorizationResponse

import javax.inject.Singleton

@Requires(property = 'spec.name', value='AuthorizationCodeControllerSpec')
@Singleton
class MockSuccessfulIdTokenAccessTokenResponseHandler implements SuccessfulIdTokenAccessTokenResponseHandler {

    @Override
    HttpResponse handle(HttpRequest request,
                        AuthorizationResponse authenticationResponse,
                        OpenIdTokenResponse idTokenAccessTokenResponse,
                        Authentication authentication) {
        HttpResponse.ok()
    }
}
