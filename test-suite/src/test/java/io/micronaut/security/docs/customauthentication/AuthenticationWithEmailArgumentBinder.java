package io.micronaut.security.docs.customauthentication;

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.convert.ArgumentConversionContext;
import io.micronaut.core.type.Argument;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.bind.binders.TypedRequestArgumentBinder;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.filters.SecurityFilter;
import jakarta.inject.Singleton;
import java.util.Optional;

@Requires(property = "spec.name", value = "CustomAuthenticationTest")
@Singleton
public class AuthenticationWithEmailArgumentBinder implements TypedRequestArgumentBinder<AuthenticationWithEmail> {
    private final Argument<AuthenticationWithEmail> argumentType;
    public AuthenticationWithEmailArgumentBinder() {
        argumentType = Argument.of(AuthenticationWithEmail.class);
    }

    @Override
    public Argument<AuthenticationWithEmail> argumentType() {
        return argumentType;
    }

    @Override
    public BindingResult<AuthenticationWithEmail> bind(ArgumentConversionContext<AuthenticationWithEmail> context, HttpRequest<?> source) {
        if (!source.getAttributes().contains(SecurityFilter.KEY)) {
            return BindingResult.UNSATISFIED;
        }
        final Optional<Authentication> existing = source.getUserPrincipal(Authentication.class);
        return existing.isPresent() ? (() -> existing.map(AuthenticationWithEmail::of)) : BindingResult.EMPTY;
    }
}
