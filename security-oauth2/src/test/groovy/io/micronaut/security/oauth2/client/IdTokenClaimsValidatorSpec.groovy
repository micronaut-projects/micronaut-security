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
    void "issuer IdTokenClaimsValidator"(String configIss, String iss) {
        given:
        def oauthClientConfiguration = new OauthClientConfigurationProperties("oci");
        def openId = new OauthClientConfigurationProperties.OpenIdClientConfigurationProperties("oci");
        openId.setIssuer(new URL(configIss))
        oauthClientConfiguration.setOpenid(openId)
        List<OauthClientConfiguration> l = List.of(oauthClientConfiguration)
        IdTokenClaimsValidator claimsValidator = new IdTokenClaimsValidator(l)

        when:
        Optional<Boolean> validation = claimsValidator.matchesIssuer(openId, iss)

        then:
        validation.isPresent()
        validation.get() == true

        where:
        configIss | iss
        "https://idcs-227ebfb7094445cc5a3fbc0faa1fe87b.identity.oraclecloud.com" | "https://identity.oraclecloud.com/"
        "https://idcs-227ebfb7094445cc5a3fbc0faa1fe87b.identity.oraclecloud.com" | "https://identity.oraclecloud.com"
        "https://identity.oraclecloud.com" | "https://identity.oraclecloud.com"
    }

    @Unroll
    void "issuer IdTokenClaimsValidator uses the issuer identifier when it differs from the issuer: #iss expected #expected"(String iss, boolean expected) {
        given:
        def oauthClientConfiguration = new OauthClientConfigurationProperties("keycloak");
        def openId = new OauthClientConfigurationProperties.OpenIdClientConfigurationProperties("keycloak");
        openId.setIssuer(new URL("http://keycloak:8080/realms/app"))
        openId.setIssuerIdentifier("https://sso.example.com/realms/app")
        oauthClientConfiguration.setOpenid(openId)
        IdTokenClaimsValidator claimsValidator = new IdTokenClaimsValidator(List.of(oauthClientConfiguration))

        when:
        Optional<Boolean> validation = claimsValidator.matchesIssuer(openId, iss)

        then:
        validation.isPresent()
        validation.get() == expected

        where:
        iss                                     | expected
        "https://sso.example.com/realms/app"    | true
        "https://sso.example.com/realms/app/"   | true
        "http://keycloak:8080/realms/app"       | false
        "https://sso.example.com/realms/other"  | false
    }

    void "issuer IdTokenClaimsValidator returns empty when neither issuer nor issuer identifier is configured"() {
        given:
        def openId = new OauthClientConfigurationProperties.OpenIdClientConfigurationProperties("manual");
        IdTokenClaimsValidator claimsValidator = new IdTokenClaimsValidator(List.of())

        expect:
        !claimsValidator.matchesIssuer(openId, "https://sso.example.com/realms/app").isPresent()
    }
}
