import java
from jakarta.inject import Singleton
from micronaut.context.annotation import Requires
from micronaut.core.bind.ArgumentBinder import BindingResult
from micronaut.core.convert import ArgumentConversionContext
from micronaut.core.type import Argument
from micronaut.http import HttpRequest
from micronaut.http.bind.binders import TypedRequestArgumentBinder
from micronaut.security.filters import SecurityFilter

from .AuthenticationWithEmail import AuthenticationWithEmail

# TODO(python): java.type needed because the imported Java interface is a wrapper that HttpRequest.getUserPrincipal()
# does not accept as the principal type ("TypeError: invalid instantiation of foreign object")
AuthenticationClass = java.type("io.micronaut.security.authentication.Authentication")
# TODO(python): java.type needed because the Python class is passed as the runtime type argument of Argument.of();
# the Python class object itself is not accepted as a Java Class
AuthenticationWithEmailClass = java.type("micronaut.security.docs.customauthentication.AuthenticationWithEmail")


@Requires(property="spec.name", value="CustomAuthenticationTest")
@Singleton
class AuthenticationWithEmailArgumentBinder(TypedRequestArgumentBinder[AuthenticationWithEmail]):
    def __init__(self):
        self.argument_type = Argument.of(AuthenticationWithEmailClass)

    def argumentType(self) -> Argument:
        return self.argument_type

    def bind(self, context: ArgumentConversionContext, source: HttpRequest) -> BindingResult:
        if not source.getAttributes().contains(SecurityFilter.KEY):
            return BindingResult.UNSATISFIED
        existing = source.getUserPrincipal(AuthenticationClass)
        if existing.isPresent():
            return lambda: existing.map(AuthenticationWithEmail.of)
        return BindingResult.EMPTY
