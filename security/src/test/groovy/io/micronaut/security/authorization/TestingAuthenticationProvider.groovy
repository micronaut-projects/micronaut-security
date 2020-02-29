package io.micronaut.security.authorization

import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.security.authentication.*
import io.reactivex.Flowable
import org.reactivestreams.Publisher
import javax.inject.Singleton

@Singleton
@Requires(property = 'spec.name', value = 'authorization')
class TestingAuthenticationProvider implements AuthenticationProvider {

    @Override
    Publisher<AuthenticationResponse> authenticate(HttpRequest<?> httpRequest, AuthenticationRequest<?, ?> authenticationRequest) {
        String username = authenticationRequest.getIdentity().toString()
        switch (username) {
            case "disabled":
                return Flowable.just(new AuthenticationFailed(AuthenticationFailureReason.USER_DISABLED))
                break
            case "accountExpired":
                return Flowable.just(new AuthenticationFailed(AuthenticationFailureReason.ACCOUNT_EXPIRED))
                break
            case "passwordExpired":
                return Flowable.just(new AuthenticationFailed(AuthenticationFailureReason.PASSWORD_EXPIRED))
                break
            case "accountLocked":
                return Flowable.just(new AuthenticationFailed(AuthenticationFailureReason.ACCOUNT_LOCKED))
                break
            case "invalidPassword":
                Flowable.just(new AuthenticationFailed(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH))
                break
            case "notFound":
                return Flowable.empty()
                break
        }
        return Flowable.just(new UserDetails(username, (username == "admin") ?  ["ROLE_ADMIN"] : ["foo", "bar"]));
    }
}
