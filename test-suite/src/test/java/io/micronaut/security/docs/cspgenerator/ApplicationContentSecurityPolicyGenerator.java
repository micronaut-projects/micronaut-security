package io.micronaut.security.docs.cspgenerator;

import io.micronaut.context.annotation.Requires;
//tag::clazz[]
import io.micronaut.http.HttpRequest;
import io.micronaut.security.csp.ContentSecurityPolicy;
import io.micronaut.security.csp.ContentSecurityPolicyDirective;
import io.micronaut.security.csp.ContentSecurityPolicyGenerator;
import jakarta.inject.Singleton;

import java.util.List;

//end::clazz[]
@Requires(property = "spec.name", value = "ApplicationContentSecurityPolicyGeneratorTest")
//tag::clazz[]
@Singleton
class ApplicationContentSecurityPolicyGenerator implements ContentSecurityPolicyGenerator {

    @Override
    public ContentSecurityPolicy contentSecurityPolicy(HttpRequest<?> request) {
        return new ContentSecurityPolicy(List.of(
            new ContentSecurityPolicyDirective(DEFAULT_SRC, QUOTED_SELF),
            new ContentSecurityPolicyDirective(OBJECT_SRC, QUOTED_NONE)));
    }
}
//end::clazz[]
