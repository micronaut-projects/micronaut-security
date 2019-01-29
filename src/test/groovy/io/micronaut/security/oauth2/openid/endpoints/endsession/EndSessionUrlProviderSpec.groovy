package io.micronaut.security.oauth2.openid.endpoints.endsession

import com.stehno.ersatz.ContentType
import com.stehno.ersatz.ErsatzServer
import io.micronaut.context.ApplicationContext
import io.micronaut.context.env.Environment
import io.micronaut.security.oauth2.configuration.OauthConfiguration
import io.micronaut.security.oauth2.openid.endpoints.OpenIdEndpoints
import io.micronaut.security.token.reader.TokenResolver
import spock.lang.Specification

class EndSessionUrlProviderSpec extends Specification {

    private static final String SPEC_NAME_PROPERTY = 'spec.name'

    void "If beans (TokenResolver, OpenIdEndpoints, OauthConfiguration, EndSessionEndpointConfiguration) are present then a EndSessionUrlProvider is loaded"() {
        given:
        String openIdConfigurationJson = 'src/test/resources/okta-openid-configuration.json'
        String path = '/oauth2/default/.well-known/openid-configuration'
        File jsonFile = new File(openIdConfigurationJson)
        assert jsonFile.exists()

        and:
        ErsatzServer ersatz = new ErsatzServer()
        ersatz.expectations {
            get(path){
                called 1
                responder {
                    body(jsonFile.text, ContentType.APPLICATION_JSON)
                }
            }
        }

        and:
        String openIdConfigurationEndpoint = "${ersatz.httpUrl}$path"
        ApplicationContext context = ApplicationContext.run([
                (SPEC_NAME_PROPERTY)                            : getClass().simpleName,
                'micronaut.security.enabled'                    : true,
                'micronaut.security.oauth2.client-id'           : 'XXX',
                'micronaut.security.oauth2.openid-configuration': openIdConfigurationEndpoint
        ], Environment.TEST)

        when:
        context.getBean(TokenResolver)

        then:
        noExceptionThrown()

        when:
        context.getBean(OpenIdEndpoints)

        then:
        noExceptionThrown()

        when:
        context.getBean(OauthConfiguration)

        then:
        noExceptionThrown()

        when:
        context.getBean(EndSessionEndpointConfiguration)

        then:
        noExceptionThrown()

        when:
        context.getBean(EndSessionUrlProvider)

        then:
        noExceptionThrown()

        and:
        ersatz.verify()

        cleanup:
        ersatz.stop()

        and:
        context.close()
    }
}
