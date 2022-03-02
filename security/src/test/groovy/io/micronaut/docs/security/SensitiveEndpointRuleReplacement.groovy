package io.micronaut.docs.security

import io.micronaut.context.annotation.Replaces
import io.micronaut.context.annotation.Requires
import io.micronaut.core.annotation.NonNull
import io.micronaut.http.HttpRequest
import io.micronaut.inject.ExecutableMethod
import io.micronaut.management.endpoint.EndpointSensitivityProcessor
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.rules.SecurityRuleResult
import io.micronaut.security.rules.SensitiveEndpointRule
import jakarta.inject.Singleton
import org.reactivestreams.Publisher
import reactor.core.publisher.Mono

@Requires(missingProperty = EXCLUSION_KEY)
//tag::preamble[]
@Singleton
@Replaces(SensitiveEndpointRule.class)
class SensitiveEndpointRuleReplacement extends SensitiveEndpointRule {

//end::preamble[]
    private static final String EXCLUSION_KEY = 'no.rule.replacement'
    static final Map<String, String> EXCLUDE_SENSITIVE_RULE_REPLACEMENT = [(EXCLUSION_KEY): 'yes']

//tag::continued[]
    SensitiveEndpointRuleReplacement(EndpointSensitivityProcessor endpointSensitivityProcessor) {
        super(endpointSensitivityProcessor);
    }

    @Override
    @NonNull
    protected Publisher<SecurityRuleResult> checkSensitiveAuthenticated(@NonNull HttpRequest<?> request,
                                                                        @NonNull Authentication authentication,
                                                                        @NonNull ExecutableMethod<?, ?> method) {
        return Mono.just(SecurityRuleResult.ALLOWED);
    }
}
//end::continued[]
