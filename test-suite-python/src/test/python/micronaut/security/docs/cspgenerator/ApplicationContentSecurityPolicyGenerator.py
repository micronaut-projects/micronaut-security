from micronaut.context.annotation import Requires
# tag::clazz[]
from jakarta.inject import Singleton
from java.util import List
from micronaut.http import HttpRequest
from micronaut.security.csp import ContentSecurityPolicy, ContentSecurityPolicyDirective, ContentSecurityPolicyDirectiveNames, ContentSecurityPolicyGenerator, ContentSecurityPolicyKeywords

# end::clazz[]
@Requires(property="spec.name", value="ApplicationContentSecurityPolicyGeneratorTest")
# tag::clazz[]
@Singleton
class ApplicationContentSecurityPolicyGenerator(ContentSecurityPolicyGenerator):

    def contentSecurityPolicy(self, request: HttpRequest) -> ContentSecurityPolicy:
        return ContentSecurityPolicy(List.of(
            ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.DEFAULT_SRC, ContentSecurityPolicyKeywords.QUOTED_SELF),
            ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.OBJECT_SRC, ContentSecurityPolicyKeywords.QUOTED_NONE)))
# end::clazz[]
