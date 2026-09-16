# tag::clazz[]
from jakarta.inject import Singleton
from micronaut.context.annotation import Replaces, Requires
from micronaut.http import HttpRequest, MutableHttpResponse
from micronaut.http.server.exceptions import ExceptionHandler
from micronaut.http.server.exceptions.response import ErrorResponseProcessor
from micronaut.security.authentication import AuthorizationException, DefaultAuthorizationExceptionHandler, WwwAuthenticateChallengeProvider
from micronaut.security.config import RedirectConfiguration, RedirectService
from micronaut.security.errors import PriorToLoginPersistence

# end::clazz[]
@Requires(property="spec.name", value="RejectionHandlerOverrideTest")
# tag::clazz[]
@Singleton
@Replaces(DefaultAuthorizationExceptionHandler)
class MyRejectionHandler(ExceptionHandler[AuthorizationException, MutableHttpResponse]):

    def __init__(self,
                 errorResponseProcessor: ErrorResponseProcessor,
                 redirectConfiguration: RedirectConfiguration,
                 redirectService: RedirectService,
                 wwwAuthenticateChallengeProviders: list[WwwAuthenticateChallengeProvider],
                 priorToLoginPersistence: PriorToLoginPersistence | None):
        # A Python class cannot extend a Java class, so delegate to the DefaultAuthorizationExceptionHandler
        self.delegate = DefaultAuthorizationExceptionHandler(errorResponseProcessor, redirectConfiguration, redirectService, wwwAuthenticateChallengeProviders, priorToLoginPersistence)

    def handle(self, request: HttpRequest, exception: AuthorizationException) -> MutableHttpResponse:
        # Let the DefaultAuthorizationExceptionHandler create the initial response
        # then add a header
        return self.delegate.handle(request, exception).header("X-Reason", "Example Header")
# end::clazz[]
