package io.micronaut.security.rules;

import edu.umd.cs.findbugs.annotations.Nullable;
import io.micronaut.core.value.PropertyResolver;
import io.micronaut.http.HttpRequest;
import io.micronaut.inject.ExecutableMethod;
import io.micronaut.management.endpoint.EndpointSensitivityProcessor;
import io.micronaut.security.token.RolesFinder;
import io.micronaut.web.router.MethodBasedRouteMatch;
import io.micronaut.web.router.RouteMatch;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Singleton;
import java.util.*;

@Singleton
public class RoleEndpointSensitiveRule extends AbstractSecurityRule {
    private static final Logger LOG = LoggerFactory.getLogger(InterceptUrlMapRule.class);

    protected final Map<ExecutableMethod, Boolean> endpointMethods;
    protected final RolesFinder rolesFinder;
    protected final String EXCLUDE_METHOD = "getHealth";
    protected final String PROPERTY_ROLES = "endpoints.roles";
    protected final ArrayList<String> requiredRoles;

    RoleEndpointSensitiveRule(
            EndpointSensitivityProcessor endpointSensitivityProcessor,
            RolesFinder rolesFinder,
            PropertyResolver propertyResolver
    ) {
        super(rolesFinder);
        this.endpointMethods = endpointSensitivityProcessor.getEndpointMethods();
        this.rolesFinder = rolesFinder;
        this.requiredRoles = new ArrayList(Arrays.asList(propertyResolver.get(PROPERTY_ROLES, String[].class).orElse(new String[0])));
        this.requiredRoles.removeAll(Collections.singleton(""));
    }

    @Override
    public SecurityRuleResult check(HttpRequest<?> request, @Nullable RouteMatch<?> routeMatch, @Nullable Map<String, Object> claims) {
        if (routeMatch instanceof MethodBasedRouteMatch) {
            ExecutableMethod method = ((MethodBasedRouteMatch) routeMatch).getExecutableMethod();

            if (endpointMethods.containsKey(method) && !method.getMethodName().equals(EXCLUDE_METHOD)) {
                if (!this.requiredRoles.isEmpty()) return super.compareRoles(this.requiredRoles, super.getRoles(claims));
            }
        }
        return SecurityRuleResult.UNKNOWN;
    }

    @Override
    public int getOrder() {
        return SensitiveEndpointRule.ORDER - 1;
    }
}
