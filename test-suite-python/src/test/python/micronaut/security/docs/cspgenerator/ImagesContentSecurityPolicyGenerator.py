# tag::clazz[]
from jakarta.inject import Singleton
from micronaut.context.annotation import Requires
from micronaut.security.csp import ContentSecurityPolicyDirective, ContentSecurityPolicyGenerator, DefaultContentSecurityPolicyGenerator
from micronaut.security.csp.conf import ContentSecurityPolicyConfiguration, ContentSecurityPolicyDirectiveConfigurations

# end::clazz[]
@Requires(property="spec.name", value="ImagesContentSecurityPolicyGeneratorTest")
# tag::clazz[]
@Singleton
class ImagesContentSecurityPolicyGenerator(DefaultContentSecurityPolicyGenerator):

    def __init__(self, cspConfiguration: ContentSecurityPolicyConfiguration,
                 directiveConfigurations: ContentSecurityPolicyDirectiveConfigurations):
        super().__init__(cspConfiguration, directiveConfigurations)

    def imgSrc(self) -> ContentSecurityPolicyDirective:
        return ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.IMG_SRC,
                                              ContentSecurityPolicyGenerator.QUOTED_SELF + " https://images.example.com")
# end::clazz[]
