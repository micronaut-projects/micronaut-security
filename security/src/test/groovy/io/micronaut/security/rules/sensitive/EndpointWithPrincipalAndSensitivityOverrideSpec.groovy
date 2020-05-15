package io.micronaut.security.rules.sensitive

import edu.umd.cs.findbugs.annotations.Nullable
import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.management.endpoint.annotation.Endpoint
import io.micronaut.management.endpoint.annotation.Read
import io.micronaut.security.EmbeddedServerSpecification

import java.security.Principal

class EndpointWithPrincipalAndSensitivityOverrideSpec extends EmbeddedServerSpecification {
    @Override
    String getSpecName() {
        'EndpointWithPrincipalAndSensitivityOverrideSpec'
    }
    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'endpoints.defaultendpoint.sensitive': false,

        ]
    }

    void "if endpoint sensitive is set to false via configuration property, it overrides default sensitive true"() {
        when:
        HttpResponse<String> response = client.exchange(HttpRequest.GET("/defaultendpoint"), String)

        then:
        response.body() == "Not logged in"
    }

    @Requires(property = 'spec.name', value = 'EndpointWithPrincipalAndSensitivityOverrideSpec')
    @Endpoint("defaultendpoint")
    static class DefaultEndpoint {

        @Read
        String hello(@Nullable Principal principal) {
            if (principal == null) {
                "Not logged in"
            } else {
                "Logged in as ${principal.name}"
            }
        }
    }
}
