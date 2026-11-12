# tag::imports[]
from jakarta.inject import Singleton
from micronaut.context.annotation import Replaces, Requires
from micronaut.http import HttpRequest
from micronaut.inject import ExecutableMethod
from micronaut.management.endpoint import EndpointSensitivityProcessor
from micronaut.security.authentication import Authentication
from micronaut.security.rules import SecurityRuleResult, SensitiveEndpointRule
from org.reactivestreams import Publisher
from reactor.core.publisher import Mono
# end::imports[]


@Requires(property="spec.name", value="SensitiveEndpointRuleReplacementTest")
# tag::clazz[]
@Singleton
@Replaces(SensitiveEndpointRule)
class SensitiveEndpointRuleReplacement(SensitiveEndpointRule):
    def __init__(self, endpointSensitivityProcessor: EndpointSensitivityProcessor):
        super().__init__(endpointSensitivityProcessor)

    def checkSensitiveAuthenticated(self, request: HttpRequest, authentication: Authentication, method: ExecutableMethod) -> Publisher[SecurityRuleResult]:
        return Mono.just(SecurityRuleResult.ALLOWED)
# end::clazz[]
