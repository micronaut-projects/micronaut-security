# tag::imports[]
import java
from jakarta.inject import Singleton
from micronaut.context.annotation import Replaces, Requires
from micronaut.http import HttpRequest
from micronaut.inject import ExecutableMethod
from micronaut.management.endpoint import EndpointSensitivityHandler, EndpointSensitivityProcessor
from micronaut.security.authentication import Authentication
from micronaut.security.rules import SecurityRule, SecurityRuleResult, SensitiveEndpointRule
from micronaut.web.router import RouteAttributes
from org.reactivestreams import Publisher
from reactor.core.publisher import Mono

# TODO(python): java.type needed because the imported Java interface is a wrapper that java.instanceof() does not
# accept as a Java class ("instanceof second argument '_MicronautJavaType' is not a Java class")
MethodBasedRouteMatch = java.type("io.micronaut.web.router.MethodBasedRouteMatch")
# end::imports[]


@Requires(property="spec.name", value="SensitiveEndpointRuleReplacementTest")
# tag::clazz[]
@Singleton
@Replaces(SensitiveEndpointRule)
class SensitiveEndpointRuleReplacement(SecurityRule[HttpRequest], EndpointSensitivityHandler):
    def __init__(self, endpointSensitivityProcessor: EndpointSensitivityProcessor):
        self.endpointMethods = endpointSensitivityProcessor.getEndpointMethods()

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
        return Mono.just(SecurityRuleResult.ALLOWED)
# end::clazz[]
