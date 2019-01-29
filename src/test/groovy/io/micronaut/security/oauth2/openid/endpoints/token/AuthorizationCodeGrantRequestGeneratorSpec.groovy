package io.micronaut.security.oauth2.openid.endpoints.token

import com.stehno.ersatz.ContentType
import com.stehno.ersatz.ErsatzServer
import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Requires
import io.micronaut.context.env.Environment
import io.micronaut.security.oauth2.configuration.OauthConfiguration
import io.micronaut.security.oauth2.openid.configuration.OpenIdProviderMetadata
import spock.lang.Specification

class AuthorizationCodeGrantRequestGeneratorSpec extends Specification {

    private static final String SPEC_NAME_PROPERTY = 'spec.name'

    void "A bean AuthorizationCodeGrantRequestGenerator is loaded"() {
        given:
        String openIdConfigurationJson = 'src/test/resources/aws-cognito-openid-configuration.json'
        String path = '/eu-west-1_ZLiEFD4b6/.well-known/openid-configuration'
        File jsonFile = new File(openIdConfigurationJson)
        assert jsonFile.exists()

        and:
        ErsatzServer ersatz = new ErsatzServer()
        ersatz.expectations {
            get(path) {
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
                'micronaut.security.oauth2.client-id'           : 'XXXX',
                'micronaut.security.oauth2.client-secret'       : 'YYYY',
                'micronaut.security.oauth2.openid-configuration': openIdConfigurationEndpoint,
                'micronaut.security.oauth2.token.redirect-uri'  : 'http://localhost:8080'
        ], Environment.TEST)

        when:
        context.getBean(OpenIdProviderMetadata)

        then:
        noExceptionThrown()

        when:
        context.getBean(TokenEndpointConfiguration)

        then:
        noExceptionThrown()

        when:
        context.getBean(OauthConfiguration.class)

        then:
        noExceptionThrown()

        when:
        context.getBean(AuthorizationCodeGrantRequestGenerator)

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
