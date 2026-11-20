package io.micronaut.security.docs.cspgenerator

//tag::clazz[]
import io.micronaut.context.annotation.Requires
import io.micronaut.security.csp.ContentSecurityPolicyDirective
import io.micronaut.security.csp.DefaultContentSecurityPolicyGenerator
import io.micronaut.security.csp.conf.ContentSecurityPolicyConfiguration
import io.micronaut.security.csp.conf.ContentSecurityPolicyDirectiveConfigurations
import jakarta.inject.Singleton

//end::clazz[]
@Requires(property = "spec.name", value = "ImagesContentSecurityPolicyGeneratorTest")
//tag::clazz[]
@Singleton
class ImagesContentSecurityPolicyGenerator extends DefaultContentSecurityPolicyGenerator {

    ImagesContentSecurityPolicyGenerator(ContentSecurityPolicyConfiguration cspConfiguration,
                                         ContentSecurityPolicyDirectiveConfigurations directiveConfigurations) {
        super(cspConfiguration, directiveConfigurations)
    }

    @Override
    protected ContentSecurityPolicyDirective imgSrc() {
        new ContentSecurityPolicyDirective(IMG_SRC, QUOTED_SELF + " https://images.example.com")
    }
}
//end::clazz[]
