package io.micronaut.security.oauth2.openid.endpoints

import com.stehno.ersatz.ContentType
import com.stehno.ersatz.ErsatzServer
import io.micronaut.context.ApplicationContext
import io.micronaut.context.env.Environment
import spock.lang.Specification

class OpenIdEndpointsSpec extends Specification {

    private static final String SPEC_NAME_PROPERTY = 'spec.name'

    void "OpenIdEndpoints is loaded"() {
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
                'micronaut.security.oauth2.openid-configuration': openIdConfigurationEndpoint
        ], Environment.TEST)

        when:
        context.getBean(OpenIdEndpoints)

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
