from jakarta.inject import Singleton
from micronaut.context.annotation import Requires
from micronaut.core.bind.ArgumentBinder import BindingResult
from micronaut.core.convert import ArgumentConversionContext
from micronaut.core.type import Argument
from micronaut.http import HttpRequest
from micronaut.http.bind.binders import TypedRequestArgumentBinder
from micronaut.security.authentication import Authentication
from micronaut.security.filters import SecurityFilter

from .AuthenticationWithEmail import AuthenticationWithEmail


@Requires(property="spec.name", value="CustomAuthenticationTest")
@Singleton
class AuthenticationWithEmailArgumentBinder(TypedRequestArgumentBinder[AuthenticationWithEmail]):
    def __init__(self):
        self.argument_type = Argument.of(AuthenticationWithEmail)

    def argumentType(self) -> Argument:
        return self.argument_type

    def bind(self, context: ArgumentConversionContext, source: HttpRequest) -> BindingResult:
        if not source.getAttributes().contains(SecurityFilter.KEY):
            return BindingResult.UNSATISFIED
        existing = source.getUserPrincipal(Authentication)
        if existing.isPresent():
            return lambda: existing.map(AuthenticationWithEmail.of)
        return BindingResult.EMPTY
