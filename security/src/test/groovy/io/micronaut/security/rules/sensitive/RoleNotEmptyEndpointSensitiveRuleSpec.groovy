package io.micronaut.security.rules.sensitive

import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.security.EmbeddedServerSpecification

class RoleNotEmptyEndpointSensitiveRuleSpec extends EmbeddedServerSpecification {
    @Override
    String getSpecName() {
        'EndpointWithRoleAndSensitivityOverrideSpec'
    }

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'endpoints.env.sensitive': false,
                'endpoints.roles': "admin,guest",

        ]
    }

    void "if endpoint has roles is set via configuration property, it overrides default list empty"() {
        when:
        HttpResponse<String> response = client.exchange(HttpRequest.GET("/env"), String)

        then:
        HttpClientResponseException e = thrown(HttpClientResponseException)
        e.status == HttpStatus.UNAUTHORIZED
    }
}

