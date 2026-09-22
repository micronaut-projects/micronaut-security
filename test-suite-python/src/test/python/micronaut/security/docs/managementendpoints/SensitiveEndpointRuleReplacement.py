# tag::imports[]
from jakarta.inject import Singleton
from micronaut.context.annotation import Replaces, Requires
from micronaut.http import HttpRequest
from micronaut.inject import ExecutableMethod
from micronaut.management.endpoint import EndpointSensitivityProcessor
from micronaut.security.authentication import Authentication
from micronaut.security.rules import SecurityRuleResult, SensitiveEndpointRule
from micronaut.security.token import RolesFinder
from org.reactivestreams import Publisher
from reactor.core.publisher import Mono
# end::imports[]


@Requires(property="spec.name", value="LoggersTest")
# tag::clazz[]
@Replaces(SensitiveEndpointRule)
@Singleton
class SensitiveEndpointRuleReplacement(SensitiveEndpointRule):
    def __init__(self, endpointSensitivityProcessor: EndpointSensitivityProcessor, rolesFinder: RolesFinder):
        super().__init__(endpointSensitivityProcessor)
        self.rolesFinder = rolesFinder

    def checkSensitiveAuthenticated(self, request: HttpRequest, authentication: Authentication, method: ExecutableMethod) -> Publisher[SecurityRuleResult]:
        if self.rolesFinder.hasAnyRequiredRoles(["ROLE_SYSTEM"], authentication.getRoles()):
            return Mono.just(SecurityRuleResult.ALLOWED)
        return Mono.just(SecurityRuleResult.REJECTED)
# end::clazz[]
