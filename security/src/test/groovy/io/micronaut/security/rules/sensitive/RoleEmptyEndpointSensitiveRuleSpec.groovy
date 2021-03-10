package io.micronaut.security.rules.sensitive

import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.security.EmbeddedServerSpecification

class RoleEmptyEndpointSensitiveRuleSpec extends EmbeddedServerSpecification {
    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'endpoints.env.sensitive': false,
                'endpoints.roles': "",

        ]
    }

    void "if endpoint has roles empty is set via configuration property"() {
        when:
        HttpResponse<String> response = client.exchange(HttpRequest.GET("/env"), String)

        then:
        response.body() != null
    }
}
