package io.micronaut.security.oauth2.docs.managementendpoints;

//tag::imports[]
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.context.annotation.Replaces;
import io.micronaut.http.HttpRequest;
import io.micronaut.inject.ExecutableMethod;
import io.micronaut.management.endpoint.EndpointSensitivityProcessor;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.rules.SecurityRuleResult;
import io.micronaut.security.rules.SensitiveEndpointRule;
import io.micronaut.security.token.RolesFinder;
import jakarta.inject.Singleton;
import java.util.Collections;
//end::imports[]

@Requires(property = "spec.name", value = "LoggersSpec")
//tag::clazz[]
@Replaces(SensitiveEndpointRule.class)
@Singleton
public class SensitiveEndpointRuleReplacement extends SensitiveEndpointRule {
    private final RolesFinder rolesFinder;

    public SensitiveEndpointRuleReplacement(EndpointSensitivityProcessor endpointSensitivityProcessor,
                                            RolesFinder rolesFinder) {
        super(endpointSensitivityProcessor);
        this.rolesFinder = rolesFinder;
    }

    @Override
    @NonNull
    protected SecurityRuleResult checkSensitiveAuthenticated(@NonNull HttpRequest<?> request,
                                                             @NonNull Authentication authentication,
                                                             @NonNull ExecutableMethod<?, ?> method) {
        return rolesFinder.hasAnyRequiredRoles(Collections.singletonList("ROLE_SYSTEM"), authentication.getRoles())
                    ? SecurityRuleResult.ALLOWED : SecurityRuleResult.REJECTED;
    }
}
//end::clazz[]
