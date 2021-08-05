package io.micronaut.security.oauth2.docs.managementendpoints

//tag::imports[]
import io.micronaut.context.annotation.Replaces
import io.micronaut.context.annotation.Requires
import io.micronaut.core.annotation.NonNull
import io.micronaut.http.HttpRequest
import io.micronaut.inject.ExecutableMethod
import io.micronaut.management.endpoint.EndpointSensitivityProcessor
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.rules.SecurityRuleResult
import io.micronaut.security.rules.SensitiveEndpointRule
import io.micronaut.security.token.RolesFinder
import jakarta.inject.Singleton
import org.reactivestreams.Publisher
import reactor.core.publisher.Mono
//end::imports[]

@Requires(property = "spec.name", value = "LoggersSpec")
//tag::clazz[]
@Replaces(SensitiveEndpointRule::class)
@Singleton
class SensitiveEndpointRuleReplacement(endpointSensitivityProcessor: EndpointSensitivityProcessor,
                                       private val rolesFinder: RolesFinder) : SensitiveEndpointRule(endpointSensitivityProcessor) {
    @NonNull
    override fun checkSensitiveAuthenticated(@NonNull request: HttpRequest<*>,
                                             @NonNull authentication: Authentication,
                                             @NonNull method: ExecutableMethod<*, *>): Publisher<SecurityRuleResult> {
        return if (rolesFinder.hasAnyRequiredRoles(listOf("ROLE_SYSTEM"), authentication)) {
            Mono.just(SecurityRuleResult.ALLOWED)
        } else {
            Mono.just(SecurityRuleResult.REJECTED)
        }
    }
}
//end::clazz[]
