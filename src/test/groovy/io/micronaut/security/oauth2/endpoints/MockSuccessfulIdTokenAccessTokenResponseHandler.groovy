package io.micronaut.security.oauth2.endpoints

import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.oauth2.handlers.SuccessfulIdTokenAccessTokenResponseHandler
import io.micronaut.security.oauth2.openid.idtoken.IdTokenAccessTokenResponse
import javax.inject.Singleton

@Requires(property = 'spec.name', value='AuthorizationCodeControllerSpec')
@Singleton
class MockSuccessfulIdTokenAccessTokenResponseHandler implements SuccessfulIdTokenAccessTokenResponseHandler {

    @Override
    HttpResponse handle(HttpRequest request, IdTokenAccessTokenResponse idTokenAccessTokenResponse, Authentication authentication) {
        HttpResponse.ok()
    }
}
