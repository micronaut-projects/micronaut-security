package io.micronaut.security.authorization

import io.micronaut.context.annotation.Replaces
import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Produces
import io.micronaut.security.EmbeddedServerSpecification
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.AuthenticationException
import io.micronaut.security.authentication.AuthenticationFailed
import io.micronaut.security.authentication.AuthenticationProvider
import io.micronaut.security.authentication.AuthenticationRequest
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.authentication.UserDetails
import io.micronaut.security.token.DefaultRolesFinder
import io.micronaut.security.token.config.TokenConfiguration
import io.reactivex.BackpressureStrategy
import io.reactivex.Flowable
import org.reactivestreams.Publisher

import javax.inject.Singleton
import java.security.Principal

class SecuredRolesCaseInsensitiveViaRolesFinderReplacementSpec extends EmbeddedServerSpecification {

    @Override
    String getSpecName() {
        'SecuredRolesCaseInsensitiveViaRolesFinderReplacementSpec'
    }

    void "@Secured annotation value is case sensitive"() {
        when:
        client.exchange(HttpRequest.GET("/uppercase").basicAuth('user', 'password'), String)

        then:
        noExceptionThrown()

        when:
        client.exchange(HttpRequest.GET("/lowercase").basicAuth('user', 'password'), String)

        then:
        noExceptionThrown()
    }

    @Requires(property = 'spec.name', value = 'SecuredRolesCaseInsensitiveViaRolesFinderReplacementSpec')
    @Singleton
    @Replaces(DefaultRolesFinder)
    static class RolesFinderReplacement extends DefaultRolesFinder {
        RolesFinderReplacement(TokenConfiguration tokenConfiguration) {
            super(tokenConfiguration)
        }

        @Override
        boolean hasAnyRequiredRoles(List<String> requiredRoles, List<String> grantedRoles) {
            for (String role : requiredRoles) {
                if (grantedRoles.stream().anyMatch(grantedRole -> grantedRole.equalsIgnoreCase(role))) {
                    return true;
                }
            }
            return false;
        }
    }

    @Requires(property = 'spec.name', value = 'SecuredRolesCaseInsensitiveViaRolesFinderReplacementSpec')
    @Controller
    static class RolesCaseInsensitiveController {

        @Produces(MediaType.TEXT_PLAIN)
        @Secured(["role_user"])
        @Get("/lowercase")
        String lowercase(Principal principal) {
            principal.name
        }

        @Produces(MediaType.TEXT_PLAIN)
        @Secured(["ROLE_USER"])
        @Get("/uppercase")
        String uppercase(Principal principal) {
            principal.name
        }
    }

    @Singleton
    @Requires(property = 'spec.name', value = 'SecuredRolesCaseInsensitiveViaRolesFinderReplacementSpec')
    static class AuthenticationProviderUserPassword implements AuthenticationProvider {

        @Override
        Publisher<AuthenticationResponse> authenticate(HttpRequest<?> httpRequest, AuthenticationRequest<?, ?> authenticationRequest) {
            Flowable.create({ emitter ->
                if ( authenticationRequest.identity == 'user' && authenticationRequest.secret == 'password' ) {
                    emitter.onNext(new UserDetails('user', ['ROLE_USER']))
                    emitter.onComplete()
                } else {
                    emitter.onError(new AuthenticationException(new AuthenticationFailed()))
                }

            }, BackpressureStrategy.ERROR)
        }
    }
}
