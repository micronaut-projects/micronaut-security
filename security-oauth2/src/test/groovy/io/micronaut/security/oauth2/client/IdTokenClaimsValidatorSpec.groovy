package io.micronaut.security.oauth2.client

import io.micronaut.security.oauth2.configuration.OauthClientConfiguration
import io.micronaut.security.oauth2.configuration.OauthClientConfigurationProperties
import io.micronaut.security.testutils.ApplicationContextSpecification
import spock.lang.Unroll

class IdTokenClaimsValidatorSpec extends ApplicationContextSpecification {

    void "by default no bean of type IdTokenClaimsValidator exists"() {
        expect:
        !applicationContext.containsBean(IdTokenClaimsValidator)
    }

    @Unroll
    void "issuer IdTokenClaimsValidator: #configIss vs #iss expected #expected"(String configIss, String iss, boolean expected) {
        given:
        def oauthClientConfiguration = new OauthClientConfigurationProperties("oci");
        def openId = new OauthClientConfigurationProperties.OpenIdClientConfigurationProperties("oci");
        openId.setIssuer(new URL(configIss))
        oauthClientConfiguration.setOpenid(openId)
        List<OauthClientConfiguration> l = [oauthClientConfiguration]
        IdTokenClaimsValidator claimsValidator = new IdTokenClaimsValidator(l)

        when:
        Optional<Boolean> validation = claimsValidator.matchesIssuer(openId, iss)

        then:
        validation.isPresent()
        validation.get() == expected

        where:
        configIss | iss | expected
        "https://identity.oraclecloud.com" | "https://identity.oraclecloud.com" | true
        "https://identity.oraclecloud.com" | "https://identity.oraclecloud.com/" | true
        // a parent domain of the configured issuer is not accepted; Oracle IDCS users set issuer-identifier instead
        "https://idcs-227ebfb7094445cc5a3fbc0faa1fe87b.identity.oraclecloud.com" | "https://identity.oraclecloud.com/" | false
        "https://idcs-227ebfb7094445cc5a3fbc0faa1fe87b.identity.oraclecloud.com" | "https://identity.oraclecloud.com" | false
    }

    @Unroll
    void "issuer IdTokenClaimsValidator accepts the Oracle IDCS provider wide issuer when configured as issuer identifier: #iss"(String iss) {
        given:
        def oauthClientConfiguration = new OauthClientConfigurationProperties("oci");
        def openId = new OauthClientConfigurationProperties.OpenIdClientConfigurationProperties("oci");
        openId.setIssuer(new URL("https://idcs-227ebfb7094445cc5a3fbc0faa1fe87b.identity.oraclecloud.com"))
        openId.setIssuerIdentifier("https://identity.oraclecloud.com/")
        oauthClientConfiguration.setOpenid(openId)
        IdTokenClaimsValidator claimsValidator = new IdTokenClaimsValidator([oauthClientConfiguration])

        expect:
        claimsValidator.matchesIssuer(openId, iss) == Optional.of(true)

        where:
        iss << ["https://identity.oraclecloud.com/", "https://identity.oraclecloud.com"]
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
