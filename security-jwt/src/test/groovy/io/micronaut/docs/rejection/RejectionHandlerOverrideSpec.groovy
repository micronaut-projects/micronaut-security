package io.micronaut.docs.rejection

import io.micronaut.context.annotation.Requires
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.security.annotation.Secured
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.token.jwt.AuthorizationUtils
import io.micronaut.security.testutils.EmbeddedServerSpecification

class RejectionHandlerOverrideSpec extends EmbeddedServerSpecification implements AuthorizationUtils {

    @Override
    String getSpecName() {
        'rejection-handler'
    }

    void "test the rejection handler can be overridden"() {
        when:
        client.exchange("/rejection-handler")

        then:
        HttpClientResponseException ex = thrown()
        ex.response.header("X-Reason") == "Example Header"
    }


    @Controller("/rejection-handler")
    @Requires(property = "spec.name", value = "rejection-handler")
    @Secured(SecurityRule.IS_AUTHENTICATED)
    static class SecuredResource {

        @Get
        String foo() {
            ""
        }

    }
}
