/*
 * Copyright 2017-2019 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.micronaut.security.oauth2.bearer

import io.micronaut.cache.CacheManager
import io.micronaut.cache.SyncCache
import io.micronaut.http.HttpResponse
import io.micronaut.http.MediaType
import io.micronaut.http.client.RxHttpClient
import io.micronaut.security.oauth2.configuration.OauthClientConfigurationProperties
import io.micronaut.security.oauth2.endpoint.AuthenticationMethod
import io.micronaut.security.oauth2.grants.GrantType
import io.reactivex.Flowable
import spock.lang.Specification

class ClientCredentialsTokenValidatorSpec extends Specification {

    TokenIntrospectionHandler tokenIntrospectionHandler = Mock()
    def introspectionHandlers = [tokenIntrospectionHandler]
    CacheManager<Object> cacheManager = Mock()
    SyncCache<Object> cache = Mock()
    RxHttpClient client = Mock()

    ClientCredentialsTokenValidator validator

    void setup() {
        cacheManager.getCache(_ as String) >> cache
        cacheManager.getCacheNames() >> []
        validator = new ClientCredentialsTokenValidator(introspectionHandlers, oauthConfiguration(), cacheManager, client)
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
        def authentication = IntrospectedToken.createActiveAuthentication("user", [], 0, 0, [:])
        client.exchange(*_) >> Flowable.just(HttpResponse.ok(["active": true]).contentType(MediaType.APPLICATION_JSON_TYPE))
        tokenIntrospectionHandler.handle(_) >> authentication

        when:
        def validationResult = validator.validateToken("some token")

        then:
        Flowable.fromPublisher(validationResult).test().assertValue(authentication)
    }

    def "token retrospection retrieved from cache"() {

        setup:
        int expirationTime = System.currentTimeSeconds() + 100
        def authentication = IntrospectedToken.createActiveAuthentication("user", [], 0, expirationTime, [:])

        when:
        this.validator = new ClientCredentialsTokenValidator(introspectionHandlers, oauthConfiguration(), cacheManager, client)
        def validationResult = validator.validateToken("some token")

        then:
        cacheManager.getCacheNames() >> ["authService"]
        cache.get("some token", IntrospectedToken) >> Optional.of(authentication)

        Flowable.fromPublisher(validationResult).test().assertValue(authentication)
    }

    def "cache expired, retrieve token from authorization service"() {

        setup:
        int expirationTime = System.currentTimeSeconds() - 100
        def authentication = IntrospectedToken.createActiveAuthentication("user", [], 0, expirationTime, [:])
        client.exchange(*_) >> Flowable.just(HttpResponse.ok(["active": true]).contentType(MediaType.APPLICATION_JSON_TYPE))
        tokenIntrospectionHandler.handle(_) >> authentication

        when:
        this.validator = new ClientCredentialsTokenValidator(introspectionHandlers, oauthConfiguration(), cacheManager, client)
        def validationResult = validator.validateToken("some token")

        then:

        cacheManager.getCacheNames() >> ["authService"]
        cache.get("some token", IntrospectedToken) >> Optional.of(authentication)

        Flowable.fromPublisher(validationResult).test().assertValue(authentication)
    }

    private static oauthConfiguration() {
        def introspectionProperties = new OauthClientConfigurationProperties.IntrospectionEndpointConfigurationProperties()

        def properties = new OauthClientConfigurationProperties('authService')
        properties.clientId = "id"
        properties.clientSecret = "secret"
        properties.introspection = introspectionProperties
        properties.grantType = GrantType.CLIENT_CREDENTIALS

        introspectionProperties.url = "http://localhost"
        introspectionProperties.authMethod = AuthenticationMethod.CLIENT_SECRET_BASIC

        return properties
    }
}
