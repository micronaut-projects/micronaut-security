package io.micronaut.security.docs.cspgenerator

import io.micronaut.context.annotation.Requires
//tag::clazz[]
import io.micronaut.http.HttpRequest
import io.micronaut.security.csp.ContentSecurityPolicyDirective
import io.micronaut.security.csp.DefaultContentSecurityPolicyGenerator
import io.micronaut.security.csp.conf.ContentSecurityPolicyConfiguration
import io.micronaut.security.csp.conf.ContentSecurityPolicyDirectiveConfigurations
import jakarta.inject.Singleton

//end::clazz[]
@Requires(property = "spec.name", value = "UpgradingContentSecurityPolicyGeneratorTest")
//tag::clazz[]
@Singleton
class UpgradingContentSecurityPolicyGenerator extends DefaultContentSecurityPolicyGenerator {

    UpgradingContentSecurityPolicyGenerator(ContentSecurityPolicyConfiguration cspConfiguration,
                                            ContentSecurityPolicyDirectiveConfigurations directiveConfigurations) {
        super(cspConfiguration, directiveConfigurations)
    }

    @Override
    protected List<ContentSecurityPolicyDirective> directives(HttpRequest<?> request) {
        super.directives(request) + new ContentSecurityPolicyDirective(UPGRADE_INSECURE_REQUESTS, null)
    }
}
//end::clazz[]
