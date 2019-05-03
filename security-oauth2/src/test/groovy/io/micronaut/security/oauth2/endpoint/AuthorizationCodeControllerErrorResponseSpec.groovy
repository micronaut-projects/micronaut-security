package io.micronaut.security.oauth2.endpoint

import io.micronaut.context.ApplicationContext
import io.micronaut.context.env.Environment
import io.micronaut.core.io.socket.SocketUtils
import io.micronaut.core.type.Argument
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpStatus
import io.micronaut.http.MediaType
import io.micronaut.http.client.RxHttpClient
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.oauth2.responses.Oauth2ErrorResponse
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification

class AuthorizationCodeControllerErrorResponseSpec extends Specification {

    static final SPEC_NAME_PROPERTY = 'spec.name'

    @Shared
    int serverPort = SocketUtils.findAvailableTcpPort()

    @Shared
    Map<String, Object> config = [
            (SPEC_NAME_PROPERTY): getClass().simpleName,
            'micronaut.server.port': serverPort,
            'micronaut.security.enabled': true,
            'micronaut.security.token.jwt.enabled': true,
            'micronaut.security.oauth2.client-id': 'XXX',
            'micronaut.security.oauth2.openid.openid-issuer': "http://localhost:$serverPort",
            'micronaut.security.oauth2.token.redirect-uri': "http://localhost:$serverPort",
            'micronaut.security.oauth2.token.url': "http://localhost:$serverPort",
    ]

    @Shared
    @AutoCleanup
    EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer, config, Environment.TEST)

    @Shared
    @AutoCleanup
    RxHttpClient client = embeddedServer.applicationContext.createBean(RxHttpClient, embeddedServer.getURL())

    void "DefaultErrorResponseHandler handles GET /authcode/cb which receives an error response"() {
        expect:
        embeddedServer.applicationContext.containsBean(AuthorizationCodeController)

        when:
        client.toBlocking().exchange(HttpRequest.GET('/authcode/cb?error=invalid_request&error_description=Unsupported%20response_type%20value&state=af0ifjsldkj'), Argument.of(Object), Argument.of(Oauth2ErrorResponse))

        then:
        HttpClientResponseException e = thrown()
        e.status == HttpStatus.BAD_REQUEST

        when:
        Optional<Oauth2ErrorResponse> errorResponseOptional = e.response.getBody(Oauth2ErrorResponse)

        then:
        errorResponseOptional.isPresent()

        when:
        Oauth2ErrorResponse errorResponse = errorResponseOptional.get()

        then:
        errorResponse.getError() == 'invalid_request'
        errorResponse.getState() == 'af0ifjsldkj'
        errorResponse.getErrorDescription() == 'Unsupported response_type value'
        errorResponse.getErrorUri() == null
    }

    void "DefaultErrorResponseHandler handles POST /authcode/cb which receives an error response"() {
        expect:
        embeddedServer.applicationContext.containsBean(AuthorizationCodeController)

        when:
        Map<String, Object> m = [error: 'invalid_request',
                                 error_description: 'Unsupported response_type value',
                                 state: 'af0ifjsldkj']
        HttpRequest request = HttpRequest.POST('/authcode/cb', m).contentType(MediaType.APPLICATION_FORM_URLENCODED)
        client.toBlocking().exchange(request, Argument.of(Object), Argument.of(Oauth2ErrorResponse))

        then:
        HttpClientResponseException e = thrown()
        e.status == HttpStatus.BAD_REQUEST

        when:
        Optional<Oauth2ErrorResponse> errorResponseOptional = e.response.getBody(Oauth2ErrorResponse)

        then:
        errorResponseOptional.isPresent()

        when:
        Oauth2ErrorResponse errorResponse = errorResponseOptional.get()

        then:
        errorResponse.getError() == 'invalid_request'
        errorResponse.getState() == 'af0ifjsldkj'
        errorResponse.getErrorDescription() == 'Unsupported response_type value'
        errorResponse.getErrorUri() == null
    }
}
