package io.micronaut.security.oauth2.grants.password.passwordflow

import io.micronaut.context.annotation.Replaces
import io.micronaut.context.annotation.Requires
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.authentication.DefaultAuthentication
import io.micronaut.security.oauth2.endpoint.token.response.validation.DefaultOpenIdTokenResponseValidator
import io.micronaut.security.oauth2.endpoints.token.response.OpenIdTokenResponse
import io.micronaut.security.oauth2.endpoint.token.response.validation.OpenIdTokenResponseValidator
import javax.inject.Singleton

@Requires(property = "spec.name", value="passwordFlow")
@Replaces(DefaultOpenIdTokenResponseValidator)
@Singleton
class DefaultIdTokenAccessTokenResponseValidatorReplacement implements OpenIdTokenResponseValidator {

    @Override
    Optional<Authentication> validate(OpenIdTokenResponse idTokenAccessTokenResponse) {
        Optional.of(new DefaultAuthentication("john", [email: 'john@email.com']))
    }
}
