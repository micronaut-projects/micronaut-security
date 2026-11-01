package io.micronaut.security.rules;

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.propagation.PropagatedContext;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.context.ServerHttpRequestContext;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.filters.SecurityFilter;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import io.micronaut.web.router.RouteAttributes;
import io.micronaut.web.router.Router;
import jakarta.inject.Inject;
import io.micronaut.core.annotation.Nullable;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * The {@code @Secured} expression must be evaluated against the request and authentication passed to the rule,
 * even when the thread is bound to the propagated context of a different request (for example after an
 * asynchronous token validation completed on another request's thread).
 */
@Property(name = "spec.name", value = "SecuredAnnotationRuleContextTest")
@MicronautTest(startApplication = false)
class SecuredAnnotationRuleContextTest {

    @Inject
    SecuredAnnotationRule rule;

    @Inject
    Router router;

    @Test
    void expressionIsEvaluatedAgainstTheAuthenticationBeingChecked() {
        assertExpressionIsEvaluatedAgainstTheAuthenticationBeingChecked();
    }

    private void assertExpressionIsEvaluatedAgainstTheAuthenticationBeingChecked() {
        HttpRequest<?> otherUsersRequest = HttpRequest.GET("/expression");
        otherUsersRequest.setAttribute(SecurityFilter.AUTHENTICATION, Authentication.build("sherlock"));
        PropagatedContext otherUsersContext = PropagatedContext.getOrEmpty().plus(new ServerHttpRequestContext(otherUsersRequest));

        otherUsersContext.propagate(() -> {
            assertEquals(SecurityRuleResult.REJECTED, check(null));
            assertEquals(SecurityRuleResult.REJECTED, check(Authentication.build("watson")));
            assertEquals(SecurityRuleResult.ALLOWED, check(Authentication.build("sherlock")));
            return null;
        });
    }

    @Test
    void expressionIsEvaluatedWithoutAnyBoundContext() {
        assertEquals(SecurityRuleResult.REJECTED, check(null));
        assertEquals(SecurityRuleResult.REJECTED, check(Authentication.build("watson")));
        assertEquals(SecurityRuleResult.ALLOWED, check(Authentication.build("sherlock")));
    }

    private SecurityRuleResult check(@Nullable Authentication authentication) {
        HttpRequest<?> request = HttpRequest.GET("/expression");
        RouteAttributes.setRouteMatch(request, router.findClosest(request));
        return Mono.from(rule.check(request, authentication)).block();
    }

    @Requires(property = "spec.name", value = "SecuredAnnotationRuleContextTest")
    @Controller("/expression")
    static class ExpressionController {

        @Secured("#{ user != null && user.name == 'sherlock' }")
        @Get
        String index() {
            return "ok";
        }
    }
}
