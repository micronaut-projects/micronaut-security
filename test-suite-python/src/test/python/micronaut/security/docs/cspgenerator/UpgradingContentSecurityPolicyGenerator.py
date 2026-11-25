from micronaut.context.annotation import Requires
# tag::clazz[]
from jakarta.inject import Singleton
from java.util import ArrayList, List
from micronaut.http import HttpRequest
from micronaut.security.csp import ContentSecurityPolicyDirective, ContentSecurityPolicyDirectiveNames, DefaultContentSecurityPolicyGenerator
from micronaut.security.csp.conf import ContentSecurityPolicyConfiguration, ContentSecurityPolicyDirectiveConfigurations

# end::clazz[]
@Requires(property="spec.name", value="UpgradingContentSecurityPolicyGeneratorTest")
# tag::clazz[]
@Singleton
class UpgradingContentSecurityPolicyGenerator(DefaultContentSecurityPolicyGenerator):

    def __init__(self, cspConfiguration: ContentSecurityPolicyConfiguration,
                 directiveConfigurations: ContentSecurityPolicyDirectiveConfigurations):
        super().__init__(cspConfiguration, directiveConfigurations)

    def directives(self, request: HttpRequest = None) -> List:
        if request is None:
            return super().directives()
        directives = ArrayList(super().directives(request))
        directives.add(ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.UPGRADE_INSECURE_REQUESTS, None))
        return directives
# end::clazz[]
