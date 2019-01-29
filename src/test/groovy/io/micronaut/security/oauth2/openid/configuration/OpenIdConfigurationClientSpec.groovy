package io.micronaut.security.oauth2.openid.configuration

import com.stehno.ersatz.ContentType
import com.stehno.ersatz.ErsatzServer
import io.micronaut.context.ApplicationContext
import io.micronaut.context.env.Environment
import io.micronaut.context.exceptions.NoSuchBeanException
import spock.lang.Specification

class OpenIdConfigurationClientSpec extends Specification {
    static final SPEC_NAME_PROPERTY = 'spec.name'

    void "OpenIdConfigurationClient is disabled by default"() {
        given:
        ApplicationContext context = ApplicationContext.run([
                (SPEC_NAME_PROPERTY):getClass().simpleName,
                'micronaut.security.enabled': true,
        ], Environment.TEST)

        when:
        context.getBean(OpenIdConfigurationClient)

        then:
        thrown(NoSuchBeanException)

        cleanup:
        context.close()
    }

    void "OpenIdConfigurationClient bean is loaded if micronaut.security.oauth2.openid-configuration is set"() {
        given:
        String openIdConfigurationJson = 'src/test/resources/auth0-openid-configuration.json'
        File jsonFile = new File(openIdConfigurationJson)
        assert jsonFile.exists()

        and:
        ErsatzServer ersatz = new ErsatzServer()
        ersatz.expectations {
            get('/.well-known/openid-configuration'){
                called 1
                responder {
                    body(jsonFile.text, ContentType.APPLICATION_JSON)
                }
            }
        }

        and:
        String openIdConfigurationEndpoint = "${ersatz.httpUrl}/.well-known/openid-configuration"
        ApplicationContext context = ApplicationContext.run([
                (SPEC_NAME_PROPERTY)                            : getClass().simpleName,
                'micronaut.security.enabled'                    : true,
                'micronaut.security.oauth2.openid-configuration': openIdConfigurationEndpoint
        ], Environment.TEST)

        when:
        context.getBean(OpenIdConfigurationClient)

        then:
        noExceptionThrown()

        when:
        context.getBean(OpenIdConfigurationFactory)

        then:
        noExceptionThrown()

        // You need to attempt to retrieve a class bean created by the factory in order for factory method to kick off
        when:
        context.getBean(OpenIdConfiguration)

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
