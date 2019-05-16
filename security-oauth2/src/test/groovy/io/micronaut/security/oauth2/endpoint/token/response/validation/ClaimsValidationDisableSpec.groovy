package io.micronaut.security.oauth2.endpoint.token.response.validation

import io.micronaut.context.ApplicationContext
import spock.lang.Specification

class ClaimsValidationDisableSpec extends Specification {

    void "test claim validators are enabled by default"() {
        given:
        ApplicationContext ctx = ApplicationContext.run([
                'micronaut.security.enabled': true,
                'micronaut.security.token.jwt.enabled': true,
                'micronaut.security.oauth2.enabled': true
        ])

        when:
        ctx.getBean(IssuerClaimValidator)
        ctx.getBean(AuthorizedPartyClaimValidator)
        ctx.getBean(AudienceClaimValidator)

        then:
        noExceptionThrown()
    }

    void "test disabling claim validators"() {
        given:
        ApplicationContext ctx = ApplicationContext.run([
                'micronaut.security.enabled': true,
                'micronaut.security.token.jwt.enabled': true,
                'micronaut.security.oauth2.enabled': true,
                'micronaut.security.oauth2.openid.claims-validation.issuer': false,
                'micronaut.security.oauth2.openid.claims-validation.audience': false,
                'micronaut.security.oauth2.openid.claims-validation.authorized-party': false
        ])

        expect:
        !ctx.findBean(IssuerClaimValidator).isPresent()
        !ctx.findBean(AuthorizedPartyClaimValidator).isPresent()
        !ctx.findBean(AudienceClaimValidator).isPresent()
    }
}
