package io.micronaut.security.docs.cspgenerator

//tag::clazz[]
import io.micronaut.context.annotation.Requires
import io.micronaut.security.csp.ContentSecurityPolicyDirective
import io.micronaut.security.csp.ContentSecurityPolicyGenerator
import io.micronaut.security.csp.DefaultContentSecurityPolicyGenerator
import io.micronaut.security.csp.conf.ContentSecurityPolicyConfiguration
import io.micronaut.security.csp.conf.ContentSecurityPolicyDirectiveConfigurations
import jakarta.inject.Singleton

//end::clazz[]
@Requires(property = "spec.name", value = "ImagesContentSecurityPolicyGeneratorTest")
//tag::clazz[]
@Singleton
class ImagesContentSecurityPolicyGenerator(
    cspConfiguration: ContentSecurityPolicyConfiguration,
    directiveConfigurations: ContentSecurityPolicyDirectiveConfigurations
) : DefaultContentSecurityPolicyGenerator(cspConfiguration, directiveConfigurations) {

    override fun imgSrc(): ContentSecurityPolicyDirective =
        ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.IMG_SRC,
            ContentSecurityPolicyGenerator.QUOTED_SELF + " https://images.example.com")
}
//end::clazz[]
