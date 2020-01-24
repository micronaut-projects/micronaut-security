package io.micronaut.security.oauth2.endpoint.token.response.validation

import io.micronaut.context.ApplicationContext
import io.micronaut.security.oauth2.ConfigurationFixture
import spock.lang.Specification

class ClaimsValidationDisableSpec extends Specification implements ConfigurationFixture {

    void "test claim validators are enabled by default"() {
        given:
        ApplicationContext ctx = ApplicationContext.run(oauth2Config)

        when:
        ctx.getBean(IssuerClaimValidator)
        ctx.getBean(AuthorizedPartyClaimValidator)
        ctx.getBean(AudienceClaimValidator)

        then:
        noExceptionThrown()
        
        cleanup:
        ctx.close()
    }

    void "test disabling claim validators"() {
        given:
        ApplicationContext ctx = ApplicationContext.run(oauth2Config + [
                'micronaut.security.oauth2.openid.claims-validation.issuer': false,
                'micronaut.security.oauth2.openid.claims-validation.audience': false,
                'micronaut.security.oauth2.openid.claims-validation.authorized-party': false
        ])

        expect:
        !ctx.findBean(IssuerClaimValidator).isPresent()
        !ctx.findBean(AuthorizedPartyClaimValidator).isPresent()
        !ctx.findBean(AudienceClaimValidator).isPresent()
       
        cleanup:
        ctx.close()
    }
}
