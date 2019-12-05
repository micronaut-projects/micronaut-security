package io.micronaut.security.oauth2.endpoint.authorization.request

import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpHeaders
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.client.DefaultHttpClientConfiguration
import io.micronaut.http.client.RxHttpClient
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.inject.qualifiers.Qualifiers
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.authentication.UserDetails
import io.micronaut.security.oauth2.OpenIDIntegrationSpec
import io.micronaut.security.oauth2.client.OauthClient
import io.micronaut.security.oauth2.client.OpenIdClient
import io.micronaut.security.oauth2.endpoint.token.response.OauthUserDetailsMapper
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse
import io.micronaut.security.oauth2.routes.OauthController
import org.reactivestreams.Publisher
import spock.lang.Specification

import javax.inject.Named
import javax.inject.Singleton
import java.nio.charset.StandardCharsets

class OpenIdAuthorizationRedirectSpec extends Specification implements OpenIDIntegrationSpec {

    void "test authorization redirect for openid and normal oauth"() {
        given:
        Map config = getConfiguration()
        config.put("micronaut.security.enabled", true)
        config.put("micronaut.security.token.jwt.enabled", true)
        config.put("micronaut.security.token.jwt.cookie.enabled", true)
        config.put('micronaut.security.oauth2.enabled', true)
        config.put("micronaut.security.oauth2.clients.keycloak.openid.issuer", ISSUER)
        config.put("micronaut.security.oauth2.clients.keycloak.client-id", "myclient")
        config.put("micronaut.security.oauth2.clients.keycloak.client-secret", CLIENT_SECRET)
        config.put("micronaut.security.oauth2.clients.twitter.authorization.url", "http://twitter.com/authorize")
        config.put("micronaut.security.oauth2.clients.twitter.token.url", "http://twitter.com/token")
        config.put("micronaut.security.oauth2.clients.twitter.client-id", "myclient")
        config.put("micronaut.security.oauth2.clients.twitter.client-secret", "mysecret")
        ApplicationContext context = startContext(config)
        EmbeddedServer embeddedServer = context.getBean(EmbeddedServer)
        embeddedServer.start()
        RxHttpClient client = context.createBean(RxHttpClient.class, embeddedServer.getURL(), new DefaultHttpClientConfiguration(followRedirects: false))

        expect:
        context.findBean(OpenIdClient, Qualifiers.byName("keycloak")).isPresent()
        context.findBean(OauthClient, Qualifiers.byName("twitter")).isPresent()
        context.findBean(OauthController, Qualifiers.byName("keycloak")).isPresent()
        context.findBean(OauthController, Qualifiers.byName("twitter")).isPresent()

        when:
        HttpResponse response = client.toBlocking().exchange("/oauth/login/keycloak")
        String location = URLDecoder.decode(response.header(HttpHeaders.LOCATION), StandardCharsets.UTF_8.toString())

        then:
        response.status == HttpStatus.FOUND
        location.startsWith(ISSUER + "/protocol/openid-connect/auth")
        location.contains("scope=openid email profile")
        location.contains("response_type=code")
        location.contains("redirect_uri=http://localhost:" + embeddedServer.getPort() + "/oauth/callback/keycloak")

        stateParser(location).contains("{\"nonce\":\"")
        location.contains("client_id=myclient")

        when:
        response = client.toBlocking().exchange("/oauth/login/twitter")
        location = URLDecoder.decode(response.header(HttpHeaders.LOCATION), StandardCharsets.UTF_8.toString())

        then:
        response.status == HttpStatus.FOUND
        location.startsWith("http://twitter.com/authorize")
        !location.contains("scope=")
        location.contains("response_type=code")
        location.contains("redirect_uri=http://localhost:" + embeddedServer.getPort() + "/oauth/callback/twitter")
        stateParser(location).contains("{\"nonce\":\"")
        location.contains("client_id=myclient")

        cleanup:
        context.close()
    }

    void "test authorization redirect with openid and oauth disabled"() {
        given:
        Map config = getConfiguration()
        config.put("micronaut.security.enabled", true)
        config.put("micronaut.security.token.jwt.enabled", true)
        config.put("micronaut.security.token.jwt.cookie.enabled", true)
        config.put('micronaut.security.oauth2.enabled', true)
        config.put("micronaut.security.oauth2.clients.keycloak.openid.issuer", ISSUER)
        config.put("micronaut.security.oauth2.clients.keycloak.client-id", "myclient")
        config.put("micronaut.security.oauth2.clients.keycloak.client-secret", CLIENT_SECRET)
        config.put("micronaut.security.oauth2.clients.twitter.authorization.url", "http://twitter.com/authorize")
        config.put("micronaut.security.oauth2.clients.twitter.token.url", "http://twitter.com/token")
        config.put("micronaut.security.oauth2.clients.twitter.client-id", "myclient")
        config.put("micronaut.security.oauth2.clients.twitter.client-secret", "mysecret")
        config.put("micronaut.security.oauth2.clients.twitter.enabled", false)
        ApplicationContext context = startContext(config)
        EmbeddedServer embeddedServer = context.getBean(EmbeddedServer)
        embeddedServer.start()
        RxHttpClient client = context.createBean(RxHttpClient.class, embeddedServer.getURL(), new DefaultHttpClientConfiguration(followRedirects: false))

        expect:
        context.findBean(OpenIdClient, Qualifiers.byName("keycloak")).isPresent()
        !context.findBean(OauthClient, Qualifiers.byName("twitter")).isPresent()
        context.findBean(OauthController, Qualifiers.byName("keycloak")).isPresent()
        !context.findBean(OauthController, Qualifiers.byName("twitter")).isPresent()

        when:
        HttpResponse response = client.toBlocking().exchange("/oauth/login/keycloak")
        String location = URLDecoder.decode(response.header(HttpHeaders.LOCATION), StandardCharsets.UTF_8.toString())

        then:
        response.status == HttpStatus.FOUND
        location.startsWith(ISSUER + "/protocol/openid-connect/auth")
        location.contains("scope=openid email profile")
        location.contains("response_type=code")
        location.contains("redirect_uri=http://localhost:" + embeddedServer.getPort() + "/oauth/callback/keycloak")
        stateParser(location).contains("{\"nonce\":\"")
        location.contains("client_id=myclient")

        when:
        client.toBlocking().exchange("/oauth/login/twitter")

        then:
        def ex = thrown(HttpClientResponseException)
        ex.response.status.code == 401

        cleanup:
        context.close()
    }

    void "test authorization redirect with just openid"() {
        given:
        Map config = getConfiguration()
        config.put("micronaut.security.enabled", true)
        config.put("micronaut.security.token.jwt.enabled", true)
        config.put("micronaut.security.token.jwt.cookie.enabled", true)
        config.put('micronaut.security.oauth2.enabled', true)
        config.put("micronaut.security.oauth2.clients.keycloak.openid.issuer", ISSUER)
        config.put("micronaut.security.oauth2.clients.keycloak.client-id", "myclient")
        config.put("micronaut.security.oauth2.clients.keycloak.client-secret", CLIENT_SECRET)
        ApplicationContext context = startContext(config)
        EmbeddedServer embeddedServer = context.getBean(EmbeddedServer)
        embeddedServer.start()
        RxHttpClient client = context.createBean(RxHttpClient.class, embeddedServer.getURL(), new DefaultHttpClientConfiguration(followRedirects: false))

        expect:
        context.findBean(OpenIdClient, Qualifiers.byName("keycloak")).isPresent()
        !context.findBean(OauthClient, Qualifiers.byName("twitter")).isPresent()
        context.findBean(OauthController, Qualifiers.byName("keycloak")).isPresent()
        !context.findBean(OauthController, Qualifiers.byName("twitter")).isPresent()

        when:
        HttpResponse response = client.toBlocking().exchange("/oauth/login/keycloak")
        String location = URLDecoder.decode(response.header(HttpHeaders.LOCATION), StandardCharsets.UTF_8.toString())

        then:
        response.status == HttpStatus.FOUND
        location.startsWith(ISSUER + "/protocol/openid-connect/auth")
        location.contains("scope=openid email profile")
        location.contains("response_type=code")
        location.contains("redirect_uri=http://localhost:" + embeddedServer.getPort() + "/oauth/callback/keycloak")
        stateParser(location).contains("{\"nonce\":\"")
        location.contains("client_id=myclient")

        when:
        client.toBlocking().exchange("/oauth/login/twitter")

        then:
        def ex = thrown(HttpClientResponseException)
        ex.response.status.code == 401

        cleanup:
        context.close()
    }

    @Singleton
    @Named("twitter")
    @Requires(property = "spec.name", value = "OpenIdAuthorizationRedirectSpec")
    @Requires(property = "micronaut.security.oauth2.clients.twitter")
    static class TwitterUserDetailsMapper implements OauthUserDetailsMapper {
        @Override
        Publisher<UserDetails> createUserDetails(TokenResponse tokenResponse) {
            return Flowable.just(new UserDetails("twitterUser", Collections.emptyList()))
        }
    }

    private String stateParser(String location) {
        String sublocation = location.substring(location.indexOf('state=') + 'state='.length())
        sublocation = sublocation.substring(0, sublocation.indexOf('&client_id='))
        new String(Base64.getUrlDecoder().decode(sublocation))
    }
}
