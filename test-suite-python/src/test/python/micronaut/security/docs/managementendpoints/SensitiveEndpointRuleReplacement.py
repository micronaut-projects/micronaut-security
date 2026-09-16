# tag::imports[]
import java
from jakarta.inject import Singleton
from micronaut.context.annotation import Replaces, Requires
from micronaut.http import HttpRequest
from micronaut.inject import ExecutableMethod
from micronaut.management.endpoint import EndpointSensitivityHandler, EndpointSensitivityProcessor
from micronaut.security.authentication import Authentication
from micronaut.security.rules import SecurityRule, SecurityRuleResult, SensitiveEndpointRule
from micronaut.security.token import RolesFinder
from micronaut.web.router import RouteAttributes
from org.reactivestreams import Publisher
from reactor.core.publisher import Mono

# TODO(python): java.type needed because the imported Java interface is a wrapper that java.instanceof() does not
# accept as a Java class ("instanceof second argument '_MicronautJavaType' is not a Java class")
MethodBasedRouteMatch = java.type("io.micronaut.web.router.MethodBasedRouteMatch")
# end::imports[]


@Requires(property="spec.name", value="LoggersTest")
# tag::clazz[]
@Replaces(SensitiveEndpointRule)
@Singleton
class SensitiveEndpointRuleReplacement(SecurityRule[HttpRequest], EndpointSensitivityHandler):
    def __init__(self, endpointSensitivityProcessor: EndpointSensitivityProcessor, rolesFinder: RolesFinder):
        self.endpointMethods = endpointSensitivityProcessor.getEndpointMethods()
        self.rolesFinder = rolesFinder

    def getOrder(self) -> int:
        return SensitiveEndpointRule.ORDER

    def check(self, request: HttpRequest, authentication: Authentication | None) -> Publisher[SecurityRuleResult]:
        routeMatch = RouteAttributes.getRouteMatch(request).orElse(None)
        if java.instanceof(routeMatch, MethodBasedRouteMatch):
            method = routeMatch.getExecutableMethod()
            if self.endpointMethods.containsKey(method):
                if not self.endpointMethods.get(method):
                    return Mono.just(SecurityRuleResult.ALLOWED)  # the endpoint is not sensitive
                if authentication is None:
                    return Mono.just(SecurityRuleResult.REJECTED)  # sensitive endpoint, anonymous request
                return self.checkSensitiveAuthenticated(request, authentication, method)
        return Mono.just(SecurityRuleResult.UNKNOWN)

    def checkSensitiveAuthenticated(self, request: HttpRequest, authentication: Authentication, method: ExecutableMethod) -> Publisher[SecurityRuleResult]:
        if self.rolesFinder.hasAnyRequiredRoles(["ROLE_SYSTEM"], authentication.getRoles()):
            return Mono.just(SecurityRuleResult.ALLOWED)
        return Mono.just(SecurityRuleResult.REJECTED)
# end::clazz[]
