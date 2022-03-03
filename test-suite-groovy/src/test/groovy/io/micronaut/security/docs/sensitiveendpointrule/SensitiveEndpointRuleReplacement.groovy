package io.micronaut.security.docs.sensitiveendpointrule

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
import jakarta.inject.Singleton
import org.reactivestreams.Publisher
import reactor.core.publisher.Mono
//end::imports[]
@Requires(property = 'spec.name', value = 'SensitiveEndpointRuleReplacementSpec')
//tag::clazz[]
@Singleton
@Replaces(SensitiveEndpointRule.class)
class SensitiveEndpointRuleReplacement extends SensitiveEndpointRule {
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
//end::clazz[]
