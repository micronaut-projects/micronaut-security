package io.micronaut.security.docs.cspgenerator

import io.micronaut.context.annotation.Requires
//tag::clazz[]
import io.micronaut.http.HttpRequest
import io.micronaut.security.csp.ContentSecurityPolicy
import io.micronaut.security.csp.ContentSecurityPolicyDirective
import io.micronaut.security.csp.ContentSecurityPolicyDirectiveNames
import io.micronaut.security.csp.ContentSecurityPolicyGenerator
import io.micronaut.security.csp.ContentSecurityPolicyKeywords
import jakarta.inject.Singleton

//end::clazz[]
@Requires(property = "spec.name", value = "ApplicationContentSecurityPolicyGeneratorTest")
//tag::clazz[]
@Singleton
class ApplicationContentSecurityPolicyGenerator : ContentSecurityPolicyGenerator {

    override fun contentSecurityPolicy(request: HttpRequest<*>): ContentSecurityPolicy =
        ContentSecurityPolicy(listOf(
            ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.DEFAULT_SRC, ContentSecurityPolicyKeywords.QUOTED_SELF),
            ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.OBJECT_SRC, ContentSecurityPolicyKeywords.QUOTED_NONE)))
}
//end::clazz[]
