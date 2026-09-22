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

//end::clazz[]
@Requires(property = "spec.name", value = "RejectionHandlerOverrideTest")
//tag::clazz[]
@Singleton
@Replaces(DefaultAuthorizationExceptionHandler::class)
class MyRejectionHandler(
    errorResponseProcessor: ErrorResponseProcessor<*>,
    redirectConfiguration: RedirectConfiguration,
    redirectService: RedirectService,
    wwwAuthenticateChallengeProviders: List<WwwAuthenticateChallengeProvider<HttpRequest<*>>>,
    priorToLoginPersistence: PriorToLoginPersistence<*, *>?
) : DefaultAuthorizationExceptionHandler(errorResponseProcessor, redirectConfiguration, redirectService, wwwAuthenticateChallengeProviders, priorToLoginPersistence) {

    override fun handle(request: HttpRequest<*>, exception: AuthorizationException): MutableHttpResponse<*> {
        //Let the DefaultAuthorizationExceptionHandler create the initial response
        //then add a header
        return super.handle(request, exception).header("X-Reason", "Example Header")
    }
}
//end::clazz[]
