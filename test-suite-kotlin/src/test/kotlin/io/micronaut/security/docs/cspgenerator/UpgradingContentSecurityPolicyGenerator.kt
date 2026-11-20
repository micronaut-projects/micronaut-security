package io.micronaut.security.docs.cspgenerator

import io.micronaut.context.annotation.Requires
//tag::clazz[]
import io.micronaut.http.HttpRequest
import io.micronaut.security.csp.ContentSecurityPolicyDirective
import io.micronaut.security.csp.ContentSecurityPolicyGenerator
import io.micronaut.security.csp.DefaultContentSecurityPolicyGenerator
import io.micronaut.security.csp.conf.ContentSecurityPolicyConfiguration
import io.micronaut.security.csp.conf.ContentSecurityPolicyDirectiveConfigurations
import jakarta.inject.Singleton

//end::clazz[]
@Requires(property = "spec.name", value = "UpgradingContentSecurityPolicyGeneratorTest")
//tag::clazz[]
@Singleton
class UpgradingContentSecurityPolicyGenerator(
    cspConfiguration: ContentSecurityPolicyConfiguration,
    directiveConfigurations: ContentSecurityPolicyDirectiveConfigurations
) : DefaultContentSecurityPolicyGenerator(cspConfiguration, directiveConfigurations) {

    override fun directives(request: HttpRequest<*>): List<ContentSecurityPolicyDirective> =
        super.directives(request) + ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.UPGRADE_INSECURE_REQUESTS, null)
}
//end::clazz[]
