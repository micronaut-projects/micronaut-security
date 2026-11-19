package io.micronaut.security.docs.cspgenerator

//tag::clazz[]
import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.security.csp.ContentSecurityPolicy
import io.micronaut.security.csp.ContentSecurityPolicyDirective
import io.micronaut.security.csp.ContentSecurityPolicyGenerator
import jakarta.inject.Singleton

//end::clazz[]
@Requires(property = "spec.name", value = "ApplicationContentSecurityPolicyGeneratorTest")
//tag::clazz[]
@Singleton
class ApplicationContentSecurityPolicyGenerator : ContentSecurityPolicyGenerator {

    override fun contentSecurityPolicy(request: HttpRequest<*>): ContentSecurityPolicy =
        ContentSecurityPolicy(listOf(
            ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.DEFAULT_SRC, ContentSecurityPolicyGenerator.QUOTED_SELF),
            ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.OBJECT_SRC, ContentSecurityPolicyGenerator.QUOTED_NONE)))
}
//end::clazz[]
