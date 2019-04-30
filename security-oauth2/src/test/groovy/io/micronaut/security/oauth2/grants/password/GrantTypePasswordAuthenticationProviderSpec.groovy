package io.micronaut.security.oauth2.grants.password

import io.micronaut.context.ApplicationContext
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration
import io.micronaut.security.oauth2.openid.endpoints.OpenIdEndpoints
import spock.lang.Shared
import spock.lang.Specification

class GrantTypePasswordAuthenticationProviderSpec extends Specification {

    @Shared
    Map<String, Object> conf = [
            'micronaut.security.enabled': true,
            'micronaut.security.token.jwt.enabled': true,
            'micronaut.security.oauth2.client-id': 'XXXXX',
            'micronaut.security.oauth2.client-secret': 'YYYYY',
    ] as Map<String, Object>


    def "GrantTypePasswordAuthenticationProvider bean is not loaded by default"() {
        given:
        ApplicationContext applicationContext = ApplicationContext.run(conf)

        expect:
        applicationContext.containsBean(GrantTypePasswordRequestProviderConfiguration)

        and:
        applicationContext.containsBean(GrantTypePasswordRequestProviderConfiguration)
        applicationContext.containsBean(OauthClientConfiguration)
        applicationContext.containsBean(OpenIdEndpoints)
        !applicationContext.containsBean(GrantTypePasswordRequestProvider)

        and:
        !applicationContext.containsBean(GrantTypePasswordAuthenticationProvider)

        cleanup:
        applicationContext.close()
    }

    def "GrantTypePasswordAuthenticationProvider bean is loaded if micronaut.security.oauth2.grant-type-password.enabled=true"() {
        given:
        Map<String, Object> specConf = new HashMap<>(conf)
        specConf["micronaut.security.oauth2.grant-type-password.enabled"] = true
        ApplicationContext applicationContext = ApplicationContext.run(specConf)

        expect:
        applicationContext.containsBean(GrantTypePasswordRequestProviderConfiguration)

        and:
        applicationContext.containsBean(GrantTypePasswordRequestProviderConfiguration)
        applicationContext.containsBean(OauthClientConfiguration)
        applicationContext.containsBean(OpenIdEndpoints)
        applicationContext.containsBean(GrantTypePasswordRequestProvider)

        and:
        applicationContext.containsBean(GrantTypePasswordAuthenticationProvider)

        cleanup:
        applicationContext.close()
    }
}
