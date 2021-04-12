package io.micronaut.security.oauth2.docs.managementendpoints

//tag::imports[]
import javax.inject.Singleton
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
//end::imports[]

@Requires(property = "spec.name", value = "LoggersSpec")
//tag::clazz[]
@Replaces(SensitiveEndpointRule.class)
@Singleton
class SensitiveEndpointRuleReplacement extends SensitiveEndpointRule {
    private final RolesFinder rolesFinder;

    SensitiveEndpointRuleReplacement(EndpointSensitivityProcessor endpointSensitivityProcessor,
                                            RolesFinder rolesFinder) {
        super(endpointSensitivityProcessor)
        this.rolesFinder = rolesFinder
    }

    @Override
    @NonNull
    protected SecurityRuleResult checkSensitiveAuthenticated(@NonNull HttpRequest<?> request,
                                                             @NonNull Map<String, Object> claims,
                                                             @NonNull ExecutableMethod<?, ?> method) {
        rolesFinder.hasAnyRequiredRoles(["ROLE_SYSTEM"], new MapClaims(claims))
                ? SecurityRuleResult.ALLOWED : SecurityRuleResult.REJECTED
    }
}
//end::clazz[]
