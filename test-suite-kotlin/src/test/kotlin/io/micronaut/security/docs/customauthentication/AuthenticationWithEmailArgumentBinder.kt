package io.micronaut.security.docs.customauthentication

import io.micronaut.context.annotation.Requires
import io.micronaut.core.bind.ArgumentBinder
import io.micronaut.core.convert.ArgumentConversionContext
import io.micronaut.core.type.Argument
import io.micronaut.http.HttpRequest
import io.micronaut.http.bind.binders.TypedRequestArgumentBinder
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.filters.SecurityFilter
import jakarta.inject.Singleton

@Requires(property = "spec.name", value = "CustomAuthenticationTest")
@Singleton
class AuthenticationWithEmailArgumentBinder : TypedRequestArgumentBinder<AuthenticationWithEmail> {
    override fun bind(context: ArgumentConversionContext<AuthenticationWithEmail>, source: HttpRequest<*>): ArgumentBinder.BindingResult<AuthenticationWithEmail> {
        if (!source.attributes.contains(SecurityFilter.KEY)) {
            return ArgumentBinder.BindingResult.unsatisfied()
        }
        val existing = source.getUserPrincipal(Authentication::class.java)
        return if (existing.isPresent) ArgumentBinder.BindingResult {
            existing.map(AuthenticationWithEmail::of)
        } else ArgumentBinder.BindingResult.empty()
    }

    override fun argumentType(): Argument<AuthenticationWithEmail> {
        return Argument.of(AuthenticationWithEmail::class.java)
    }
}
