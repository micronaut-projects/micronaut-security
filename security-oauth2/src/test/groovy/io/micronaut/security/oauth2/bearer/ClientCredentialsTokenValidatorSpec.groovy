package io.micronaut.security.oauth2.bearer

import io.micronaut.http.HttpResponse
import io.micronaut.http.MediaType
import io.micronaut.http.MutableHttpRequest
import io.micronaut.http.client.RxHttpClient
import io.reactivex.Flowable
import spock.lang.Specification

class ClientCredentialsTokenValidatorSpec extends Specification {

    def tokenIntrospectionConfiguration = new BearerTokenIntrospectionProperties()
    TokenIntrospectionHandler tokenIntrospectionHandler = Mock()
    def introspectionHandlers = [tokenIntrospectionHandler]
    RxHttpClient client = Mock()
    IntrospectionEndpointAuthStrategy authStrategy = Mock()

    ClientCredentialsTokenValidator validator;

    void setup() {
        validator = new ClientCredentialsTokenValidator(tokenIntrospectionConfiguration, introspectionHandlers, authStrategy, client)
    }

    def "unauthorized access to introspection endpoint"() {

        setup:
        authStrategy.authorizeRequest(_) >> {MutableHttpRequest request -> request}
        client.exchange(*_) >> Flowable.just(HttpResponse.unauthorized())

        when:
        def validationResult = validator.validateToken("some token")

        then:
        Flowable.fromPublisher(validationResult).test().assertNoValues()
    }

    def "5xx for a call to introspection endpoint"() {

        setup:
        authStrategy.authorizeRequest(_) >> {MutableHttpRequest request -> request}
        client.exchange(*_) >> Flowable.just(HttpResponse.serverError())

        when:
        def validationResult = validator.validateToken("some token")

        then:
        Flowable.fromPublisher(validationResult).test().assertNoValues()
    }

    def "introspection endpoint does not return valid body"() {

        setup:
        authStrategy.authorizeRequest(_) >> {MutableHttpRequest request -> request}
        client.exchange(*_) >> Flowable.just(HttpResponse.ok())

        when:
        def validationResult = validator.validateToken("some token")

        then:
        Flowable.fromPublisher(validationResult).test().assertNoValues()
    }

    def "successful token validation"() {

        setup:
        def authentication = IntrospectedToken.createActiveAuthentication("user", [], [:])
        authStrategy.authorizeRequest(_) >> {MutableHttpRequest request -> request}
        client.exchange(*_) >> Flowable.just(HttpResponse.ok(["active": true]).contentType(MediaType.APPLICATION_JSON_TYPE))
        tokenIntrospectionHandler.handle(_) >> authentication

        when:
        def validationResult = validator.validateToken("some token")

        then:
        Flowable.fromPublisher(validationResult).test().assertValue(authentication)
    }
}
