package io.micronaut.security

import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.testutils.EmbeddedServerSpecification

class ClientAuthenticationSpec extends EmbeddedServerSpecification {

    @Override
    String getSpecName() {
        'ClientAuthenticationSpec'
    }

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.authentication'   : 'bearer',
                'micronaut.security.token.jwt.signatures.secret.generator.secret': 'pleaseChangeThisSecretForANewOne',
        ]
    }

    void "ClientAuthentication is used to bind a JSON object with name and attributes fields into an Authentication"() {
        when:
        Authentication authentication = client.retrieve(HttpRequest.GET('/nightwatch'), Authentication)

        then:
        noExceptionThrown()
        authentication.name == 'john'
        authentication.roles == ['ROLE_NIGHT_WATCH']
        authentication.attributes == [birthname: 'Aegon', roles: ['ROLE_NIGHT_WATCH']]
    }

    void "ClientAuthentication manages custom rolesKey to bind roles"() {
        when:
        Authentication authentication = client.retrieve(HttpRequest.GET('/rolesKey'), Authentication)

        then:
        noExceptionThrown()
        authentication.name == 'john'
        authentication.roles == ['ROLE_NIGHT_WATCH']
        authentication.attributes == [birthname: 'Aegon', rolesKey: 'groups', groups: ['ROLE_NIGHT_WATCH']]
    }

    void "ClientAuthentication binds to Authentication the JSON Payload returned by a controller method which returns Authentication"() {
        when:
        Authentication authentication = client.retrieve(HttpRequest.GET('/auth'), Authentication)

        then:
        noExceptionThrown()
        authentication.name == 'john'
        authentication.roles == ['ROLE_NIGHT_WATCH']
        authentication.attributes == [birthname: 'Aegon', roles: ['ROLE_NIGHT_WATCH']]
    }

    @Requires(property = 'spec.name', value = 'ClientAuthenticationSpec')
    @Controller
    static class NightWatchController {
        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get("/nightwatch")
        Map<String, Object> nightwatch() {
            [name: 'john', attributes: ['roles': ['ROLE_NIGHT_WATCH'], 'birthname': 'Aegon']]
        }

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get("/rolesKey")
        Map<String, Object> rolesKey() {
            [name: 'john', attributes: [rolesKey: 'groups', groups: ['ROLE_NIGHT_WATCH'], birthname: 'Aegon']]
        }

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get("/auth")
        Authentication auth() {
            Authentication.build('john', ['ROLE_NIGHT_WATCH'], [birthname: 'Aegon'])
        }
    }
}
