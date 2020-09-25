package io.micronaut.security.endpoints.introspection

import edu.umd.cs.findbugs.annotations.Nullable
import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.MediaType
import io.micronaut.security.EmbeddedServerSpecification
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.authentication.AuthenticationUserDetailsAdapter
import io.micronaut.security.authentication.UserDetails
import io.micronaut.security.token.config.TokenConfiguration
import io.micronaut.security.token.validator.TokenValidator
import io.reactivex.Flowable
import org.reactivestreams.Publisher

import javax.inject.Singleton

class IntrospectionControllerPathConfigurableSpec extends EmbeddedServerSpecification {
    @Override
    String getSpecName() {
        'IntrospectionControllerPathConfigurableSpec'
    }
    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.endpoints.introspection.path': '/introspection',
        ]
    }

    def "the path of the introspection endpoint can be changed with micronaut.security.endpoints.introspection.path"() {
        when:
        HttpRequest request = HttpRequest.POST("/introspection", new IntrospectionRequest("XXX"))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
        HttpResponse<Map> response = client.exchange(request, Map)

        then:
        noExceptionThrown()
        response.status() == HttpStatus.OK
    }

    @Requires(property = 'spec.name', value = 'IntrospectionControllerPathConfigurableSpec')
    @Singleton
    static class CustomTokenValidator implements TokenValidator {

        @Override
        Publisher<Authentication> validateToken(String token) {
            validateToken(token, null)
        }

        @Override
        Publisher<Authentication> validateToken(String token, @Nullable HttpRequest<?> request) {
            UserDetails ud = new UserDetails('user', ['ROLE_ADMIN', 'ROLE_USER'], [email: 'john@micronaut.io'])
            Authentication authentication = new AuthenticationUserDetailsAdapter(ud, TokenConfiguration.DEFAULT_ROLES_NAME, TokenConfiguration.DEFAULT_NAME_KEY)
            if (token == "2YotnFZFEjr1zCsicMWpAA") {
                return Flowable.just(authentication)
            }
            return Flowable.empty()
        }
    }

}
