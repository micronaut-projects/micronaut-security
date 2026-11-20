from micronaut.context.annotation import Requires
# tag::clazz[]
from jakarta.inject import Singleton
from java.util import List
from micronaut.http import HttpRequest
from micronaut.security.csp import ContentSecurityPolicy, ContentSecurityPolicyDirective, ContentSecurityPolicyGenerator

# end::clazz[]
@Requires(property="spec.name", value="ApplicationContentSecurityPolicyGeneratorTest")
# tag::clazz[]
@Singleton
class ApplicationContentSecurityPolicyGenerator(ContentSecurityPolicyGenerator):

    def contentSecurityPolicy(self, request: HttpRequest) -> ContentSecurityPolicy:
        return ContentSecurityPolicy(List.of(
            ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.DEFAULT_SRC, ContentSecurityPolicyGenerator.QUOTED_SELF),
            ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.OBJECT_SRC, ContentSecurityPolicyGenerator.QUOTED_NONE)))
# end::clazz[]
