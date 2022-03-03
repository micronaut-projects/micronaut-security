package io.micronaut.security.docs.managementendpoints

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

//tag::imports[]

import org.reactivestreams.Publisher
import reactor.core.publisher.Mono

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
    protected Publisher<SecurityRuleResult> checkSensitiveAuthenticated(@NonNull HttpRequest<?> request,
                                                                        @NonNull Authentication authentication,
                                                                        @NonNull ExecutableMethod<?, ?> method) {
        Mono.just(rolesFinder.hasAnyRequiredRoles(["ROLE_SYSTEM"], authentication.roles)
                ? SecurityRuleResult.ALLOWED : SecurityRuleResult.REJECTED)
    }
}
//end::clazz[]
