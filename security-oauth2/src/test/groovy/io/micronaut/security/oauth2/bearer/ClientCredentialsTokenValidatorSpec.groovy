package io.micronaut.security.oauth2.bearer

import io.micronaut.http.HttpResponse
import io.micronaut.http.MediaType
import io.micronaut.http.MutableHttpRequest
import io.micronaut.http.client.RxHttpClient
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration
import io.micronaut.security.oauth2.configuration.OauthClientConfigurationProperties
import io.micronaut.security.oauth2.endpoint.AuthenticationMethod
import io.micronaut.security.oauth2.grants.GrantType
import io.reactivex.Flowable
import spock.lang.Specification

class ClientCredentialsTokenValidatorSpec extends Specification {

    TokenIntrospectionHandler tokenIntrospectionHandler = Mock()
    def introspectionHandlers = [tokenIntrospectionHandler]
    RxHttpClient client = Mock()

    ClientCredentialsTokenValidator validator;

    void setup() {
        validator = new ClientCredentialsTokenValidator(introspectionHandlers, oauthConfiguration(), client)
    }

    def "unauthorized access to introspection endpoint"() {

        setup:
        client.exchange(*_) >> Flowable.just(HttpResponse.unauthorized())

        when:
        def validationResult = validator.validateToken("some token")

        then:
        Flowable.fromPublisher(validationResult).test().assertNoValues()
    }

    def "5xx for a call to introspection endpoint"() {

        setup:
        client.exchange(*_) >> Flowable.just(HttpResponse.serverError())

        when:
        def validationResult = validator.validateToken("some token")

        then:
        Flowable.fromPublisher(validationResult).test().assertNoValues()
    }

    def "introspection endpoint does not return valid body"() {

        setup:
        client.exchange(*_) >> Flowable.just(HttpResponse.ok())

        when:
        def validationResult = validator.validateToken("some token")

        then:
        Flowable.fromPublisher(validationResult).test().assertNoValues()
    }

    def "successful token validation"() {

        setup:
        def authentication = IntrospectedToken.createActiveAuthentication("user", [], [:])
        client.exchange(*_) >> Flowable.just(HttpResponse.ok(["active": true]).contentType(MediaType.APPLICATION_JSON_TYPE))
        tokenIntrospectionHandler.handle(_) >> authentication

        when:
        def validationResult = validator.validateToken("some token")

        then:
        Flowable.fromPublisher(validationResult).test().assertValue(authentication)
    }

    private static oauthConfiguration() {
        def introspectionProperties = new OauthClientConfigurationProperties.IntrospectionEndpointConfigurationProperties()

        def properties = new OauthClientConfigurationProperties()
        properties.clientId = "id"
        properties.clientSecret = "secret"
        properties.introspection = introspectionProperties
        properties.grantType = GrantType.CLIENT_CREDENTIALS

        introspectionProperties.url = "http://localhost"
        introspectionProperties.authMethod = AuthenticationMethod.CLIENT_SECRET_BASIC

        return properties
    }
}
