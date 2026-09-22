package io.micronaut.security.docs.rejection

//tag::clazz[]
import io.micronaut.context.annotation.Replaces
import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.MutableHttpResponse
import io.micronaut.http.server.exceptions.response.ErrorResponseProcessor
import io.micronaut.security.authentication.AuthorizationException
import io.micronaut.security.authentication.DefaultAuthorizationExceptionHandler
import io.micronaut.security.authentication.WwwAuthenticateChallengeProvider
import io.micronaut.security.config.RedirectConfiguration
import io.micronaut.security.config.RedirectService
import io.micronaut.security.errors.PriorToLoginPersistence
import jakarta.inject.Singleton
import org.jspecify.annotations.Nullable

//end::clazz[]
@Requires(property = "spec.name", value = "RejectionHandlerOverrideTest")
//tag::clazz[]
@Singleton
@Replaces(DefaultAuthorizationExceptionHandler)
class MyRejectionHandler extends DefaultAuthorizationExceptionHandler {

    MyRejectionHandler(ErrorResponseProcessor<?> errorResponseProcessor,
                       RedirectConfiguration redirectConfiguration,
                       RedirectService redirectService,
                       List<WwwAuthenticateChallengeProvider<HttpRequest<?>>> wwwAuthenticateChallengeProviders,
                       @Nullable PriorToLoginPersistence priorToLoginPersistence) {
        super(errorResponseProcessor, redirectConfiguration, redirectService, wwwAuthenticateChallengeProviders, priorToLoginPersistence)
    }

    @Override
    MutableHttpResponse<?> handle(HttpRequest request, AuthorizationException exception) {
        //Let the DefaultAuthorizationExceptionHandler create the initial response
        //then add a header
        super.handle(request, exception).header("X-Reason", "Example Header")
    }
}
//end::clazz[]
