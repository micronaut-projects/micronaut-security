package io.micronaut.security.docs.customauthentication

import io.micronaut.context.annotation.Requires
import io.micronaut.core.convert.ArgumentConversionContext
import io.micronaut.core.type.Argument
import io.micronaut.http.HttpRequest
import io.micronaut.http.bind.binders.TypedRequestArgumentBinder
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.filters.SecurityFilter
import jakarta.inject.Singleton

@Requires(property = "spec.name", value = "CustomAuthenticationTest")
@Singleton
class AuthenticationWithEmailArgumentBinder implements TypedRequestArgumentBinder<AuthenticationWithEmail> {
    private final Argument<AuthenticationWithEmail> argumentType;
    AuthenticationWithEmailArgumentBinder() {
        argumentType = Argument.of(AuthenticationWithEmail.class);
    }

    @Override
    Argument<AuthenticationWithEmail> argumentType() {
        return argumentType;
    }

    @Override
    BindingResult<AuthenticationWithEmail> bind(ArgumentConversionContext<AuthenticationWithEmail> context, HttpRequest<?> source) {
        if (!source.getAttributes().contains(SecurityFilter.KEY)) {
            return BindingResult.UNSATISFIED
        }
        final Optional<Authentication> existing = source.getUserPrincipal(Authentication.class)
        existing.isPresent() ? (() -> existing.map(AuthenticationWithEmail::of)) : BindingResult.EMPTY
    }
}
