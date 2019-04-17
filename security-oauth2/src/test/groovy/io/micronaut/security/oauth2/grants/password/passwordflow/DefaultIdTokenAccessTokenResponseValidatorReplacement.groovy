package io.micronaut.security.oauth2.grants.password.passwordflow

import io.micronaut.context.annotation.Replaces
import io.micronaut.context.annotation.Requires
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.authentication.DefaultAuthentication
import io.micronaut.security.oauth2.openid.idtoken.DefaultIdTokenAccessTokenResponseValidator
import io.micronaut.security.oauth2.openid.idtoken.IdTokenAccessTokenResponse
import io.micronaut.security.oauth2.openid.idtoken.IdTokenAccessTokenResponseValidator
import javax.inject.Singleton

@Requires(property = "spec.name", value="passwordFlow")
@Replaces(DefaultIdTokenAccessTokenResponseValidator)
@Singleton
class DefaultIdTokenAccessTokenResponseValidatorReplacement implements IdTokenAccessTokenResponseValidator {

    @Override
    Optional<Authentication> validate(IdTokenAccessTokenResponse idTokenAccessTokenResponse) {
        Optional.of(new DefaultAuthentication("john", [email: 'john@email.com']))
    }
}
