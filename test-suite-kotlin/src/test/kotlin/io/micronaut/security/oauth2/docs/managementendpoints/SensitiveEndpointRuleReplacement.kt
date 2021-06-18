package io.micronaut.security.oauth2.docs.managementendpoints

//tag::imports[]
import io.micronaut.context.annotation.Replaces
import io.micronaut.context.annotation.Requires
import io.micronaut.core.annotation.NonNull
import io.micronaut.http.HttpRequest
import io.micronaut.inject.ExecutableMethod
import io.micronaut.management.endpoint.EndpointSensitivityProcessor
import io.micronaut.security.rules.SecurityRuleResult
import io.micronaut.security.rules.SensitiveEndpointRule
import io.micronaut.security.token.MapClaims
import io.micronaut.security.token.RolesFinder
import jakarta.inject.Singleton
//end::imports[]

@Requires(property = "spec.name", value = "LoggersSpec")
//tag::clazz[]
@Replaces(SensitiveEndpointRule::class)
@Singleton
class SensitiveEndpointRuleReplacement(endpointSensitivityProcessor: EndpointSensitivityProcessor,
                                       private val rolesFinder: RolesFinder) : SensitiveEndpointRule(endpointSensitivityProcessor) {
    @NonNull
    override fun checkSensitiveAuthenticated(@NonNull request: HttpRequest<*>,
                                             @NonNull claims: Map<String, Any>,
                                             @NonNull method: ExecutableMethod<*, *>): SecurityRuleResult {
        return if (rolesFinder.hasAnyRequiredRoles(listOf("ROLE_SYSTEM"), MapClaims(claims))) SecurityRuleResult.ALLOWED else SecurityRuleResult.REJECTED
    }
}
//end::clazz[]