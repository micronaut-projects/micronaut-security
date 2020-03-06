package io.micronaut.security.session

import io.micronaut.context.annotation.Replaces
import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.MutableHttpResponse
import io.micronaut.http.server.exceptions.ExceptionHandler
import io.micronaut.security.authentication.AuthenticationException
import io.micronaut.security.authentication.AuthorizationException

import javax.inject.Singleton

@Requires(property = 'spec.name', value = "RejectionHandlerResolutionSpec")
@Singleton
@Replaces(RedirectingAuthorizationExceptionHandler)
class ExtendedSessionSecurityfilterRejectionHandler implements ExceptionHandler<AuthorizationException, MutableHttpResponse<?>> {

    @Override
    MutableHttpResponse<?> handle(HttpRequest request, AuthorizationException exception) {
        return null
    }
}
