package io.micronaut.security.errors

import com.fasterxml.jackson.annotation.JsonProperty
import io.micronaut.context.annotation.Requires
import io.micronaut.core.annotation.Introspected
import io.micronaut.core.type.Argument
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpStatus
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Status
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.security.testutils.EmbeddedServerSpecification
import io.micronaut.security.annotation.Secured
import io.micronaut.security.rules.SecurityRule

class OauthErrorResponseExceptionHandlerSpec extends EmbeddedServerSpecification {

    void "A OauthErrorResponseException is handled as a 400 with JSON error error_description error_uri JSON"() {
        when:
        HttpRequest request = HttpRequest.GET('/throwsoautherrorresponse')
        Argument<String> bodyType =  Argument.of(String)
        Argument<CustomErrorResponse> errorType =  Argument.of(CustomErrorResponse)
        client.exchange(request, bodyType, errorType)

        then:
        HttpClientResponseException e = thrown()
        e.response.status() == HttpStatus.BAD_REQUEST

        when:
        Optional<CustomErrorResponse> errorResponseOptional = e.response.getBody(CustomErrorResponse)

        then:
        errorResponseOptional.isPresent()

        when:
        CustomErrorResponse errorResponse = errorResponseOptional.get()

        then:
        errorResponse.error
        errorResponse.error == 'unauthorized_client'
        errorResponse.errorDescription == "error description"
        errorResponse.errorUri == "error uri"
    }

    @Override
    String getSpecName() {
        'OauthErrorResponseExceptionHandlerSpec'
    }

    @Requires(property = 'spec.name', value = 'OauthErrorResponseExceptionHandlerSpec')
    @Controller("/throwsoautherrorresponse")
    static class ThrowsOauthErrorResponseController {

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Status(HttpStatus.OK)
        @Get
        void index() {
            throw new OauthErrorResponseException(IssuingAnAccessTokenErrorCode.UNAUTHORIZED_CLIENT, "error description", "error uri")
        }
    }

    @Introspected
    static class CustomErrorResponse {
        String error

        @JsonProperty("error_description")
        String errorDescription

        @JsonProperty("error_uri")
        String errorUri
    }
}
