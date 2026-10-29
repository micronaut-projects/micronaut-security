package io.micronaut.security.oauth2.client

import io.micronaut.security.oauth2.configuration.OauthClientConfigurationProperties
import io.micronaut.security.testutils.ApplicationContextSpecification
import spock.lang.Unroll

class IdTokenClaimsValidatorSpec extends ApplicationContextSpecification {

    void "by default no bean of type IdTokenClaimsValidator exists"() {
        expect:
        !applicationContext.containsBean(IdTokenClaimsValidator)
    }

    @Unroll
    void "issuer IdTokenClaimsValidator uses the issuer identifier when it differs from the issuer: #iss expected #expected"(String iss, boolean expected) {
        given:
        def oauthClientConfiguration = new OauthClientConfigurationProperties("keycloak");
        def openId = new OauthClientConfigurationProperties.OpenIdClientConfigurationProperties("keycloak");
        openId.setIssuer(new URL("http://keycloak:8080/realms/app"))
        openId.setIssuerIdentifier("https://sso.example.com/realms/app")
        oauthClientConfiguration.setOpenid(openId)
        IdTokenClaimsValidator claimsValidator = new IdTokenClaimsValidator([oauthClientConfiguration])

        when:
        Optional<Boolean> validation = claimsValidator.matchesIssuer(openId, iss)

        then:
        validation.isPresent()
        validation.get() == expected

        where:
        iss                                     | expected
        "https://sso.example.com/realms/app"    | true
        "HTTPS://sso.example.com/realms/app"    | true
        "http://keycloak:8080/realms/app"       | false
        "https://sso.example.com/realms/other"  | false
    }

    void "issuer IdTokenClaimsValidator uses the issuer when no issuer identifier is configured"() {
        given:
        def openId = new OauthClientConfigurationProperties.OpenIdClientConfigurationProperties("keycloak");
        openId.setIssuer(new URL("https://sso.example.com/realms/app"))
        IdTokenClaimsValidator claimsValidator = new IdTokenClaimsValidator([])

        expect:
        claimsValidator.matchesIssuer(openId, "https://sso.example.com/realms/app").get()
        !claimsValidator.matchesIssuer(openId, "https://sso.example.com/realms/other").get()
    }

    void "issuer IdTokenClaimsValidator returns empty when neither issuer nor issuer identifier is configured"() {
        given:
        def openId = new OauthClientConfigurationProperties.OpenIdClientConfigurationProperties("manual");
        IdTokenClaimsValidator claimsValidator = new IdTokenClaimsValidator([])

        expect:
        !claimsValidator.matchesIssuer(openId, "https://sso.example.com/realms/app").isPresent()
    }
}
