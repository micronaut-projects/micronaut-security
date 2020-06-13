package io.micronaut.security.authentication

import groovy.transform.AutoImplement
import io.micronaut.security.config.AuthenticationStrategy
import io.micronaut.security.config.SecurityConfiguration
import io.micronaut.security.config.SecurityConfigurationProperties
import io.micronaut.security.token.config.TokenConfiguration
import io.reactivex.BackpressureStrategy
import io.reactivex.Flowable
import spock.lang.Shared
import spock.lang.Specification

import static io.reactivex.Flowable.create

class AuthenticatorSpec extends Specification {

    @Shared
    SecurityConfiguration ALL = new AllSecurityConfiguration()

    @AutoImplement
    static class AllSecurityConfiguration implements SecurityConfiguration {
        @Override
        AuthenticationStrategy getAuthenticationProviderStrategy() {
            return AuthenticationStrategy.ALL
        }
    }

    void "if no authentication providers return empty optional"() {
        given:
        Authenticator authenticator = new Authenticator([], new SecurityConfigurationProperties())

        when:
        def creds = new UsernamePasswordCredentials('admin', 'admin')
        Flowable<AuthenticationResponse> rsp = Flowable.fromPublisher(authenticator.authenticate(null, creds))
        rsp.blockingFirst()

        then:
        thrown(NoSuchElementException)
    }

    void "if any authentication provider throws exception, continue with authentication"() {
        given:
        def authProviderExceptionRaiser = Stub(AuthenticationProvider) {
            authenticate(_, _) >> { Flowable.error( new Exception('Authentication provider raised exception') ) }
        }
        def authProviderOK = Stub(AuthenticationProvider) {
            authenticate(_, _) >> create({emitter ->
                emitter.onNext(AuthenticationResponse.build("admin", new TokenConfiguration() {}))
                emitter.onComplete()
            }, BackpressureStrategy.ERROR)
        }
        Authenticator authenticator = new Authenticator([authProviderExceptionRaiser, authProviderOK], new SecurityConfigurationProperties())

        when:
        def creds = new UsernamePasswordCredentials('admin', 'admin')
        Flowable<AuthenticationResponse> rsp = authenticator.authenticate(null, creds)

        then:
        rsp.blockingFirst() instanceof AuthenticationResponse
        rsp.blockingFirst().isAuthenticated()
    }

    void "if no authentication provider can authentication, the last error is sent back"() {
        given:
        def authProviderFailed = Stub(AuthenticationProvider) {
            authenticate(_, _) >> create({ emitter ->
                emitter.onError(new AuthenticationException(new AuthenticationFailed()))
                emitter.onComplete()
            }, BackpressureStrategy.ERROR)
        }
        Authenticator authenticator = new Authenticator([authProviderFailed], new SecurityConfigurationProperties())

        when:
        UsernamePasswordCredentials creds = new UsernamePasswordCredentials('admin', 'admin')
        Flowable<AuthenticationResponse> rsp = Flowable.fromPublisher(authenticator.authenticate(null, creds))

        then:
        rsp.blockingFirst() instanceof AuthenticationFailed
    }

    void "test authentication strategy all with error and empty"() {
        given:
        def providers = [
                Stub(AuthenticationProvider) {
                    authenticate(_, _) >> create({ emitter ->
                        emitter.onError(new AuthenticationException(new AuthenticationFailed("failed")))
                        emitter.onComplete()
                    }, BackpressureStrategy.ERROR)
                },
                Stub(AuthenticationProvider) {
                    authenticate(_, _) >> Flowable.empty()
                },
                Stub(AuthenticationProvider) {
                    authenticate(_, _) >> create({ emitter ->
                        emitter.onNext(AuthenticationResponse.build("a", new TokenConfiguration() {}))
                        emitter.onComplete()
                    }, BackpressureStrategy.ERROR)
                },
        ]
        Authenticator authenticator = new Authenticator(providers, ALL)

        when:
        def creds = new UsernamePasswordCredentials('admin', 'admin')
        AuthenticationResponse rsp = Flowable.fromPublisher(authenticator.authenticate(null, creds)).blockingFirst()

        then: //The last error is returned
        rsp instanceof AuthenticationFailed
        rsp.message.get() == "Provider did not respond. Authentication rejected"
    }

    void "test authentication strategy all with error"() {
        given:
        def providers = [
                Stub(AuthenticationProvider) {
                    authenticate(_, _) >>  create({ emitter ->
                        emitter.onError(new AuthenticationException(new AuthenticationFailed("failed")))
                        emitter.onComplete()
                    }, BackpressureStrategy.ERROR)
                },
                Stub(AuthenticationProvider) {
                    authenticate(_, _) >>  create({ emitter ->
                        emitter.onNext(AuthenticationResponse.build("a", new TokenConfiguration() {}))
                        emitter.onComplete()
                    }, BackpressureStrategy.ERROR)
                },
        ]
        Authenticator authenticator = new Authenticator(providers, ALL)

        when:
        def creds = new UsernamePasswordCredentials('admin', 'admin')
        AuthenticationResponse rsp = Flowable.fromPublisher(authenticator.authenticate(null, creds)).blockingFirst()

        then: //The last error is returned
        rsp instanceof AuthenticationFailed
        rsp.message.get() == "failed"
    }

    void "test authentication strategy success first"() {
        given:
        def providers = [
                Stub(AuthenticationProvider) {
                    authenticate(_, _) >> create({ emitter ->
                        emitter.onNext(AuthenticationResponse.build("a", new TokenConfiguration() {}))
                        emitter.onComplete()
                    }, BackpressureStrategy.ERROR)
                },
                Stub(AuthenticationProvider) {
                    authenticate(_, _) >> create({ emitter ->
                        emitter.onError(new AuthenticationException(new AuthenticationFailed("failed")))
                        emitter.onComplete()
                    }, BackpressureStrategy.ERROR)
                },
        ]
        Authenticator authenticator = new Authenticator(providers, ALL)

        when:
        def creds = new UsernamePasswordCredentials('admin', 'admin')
        AuthenticationResponse rsp = Flowable.fromPublisher(authenticator.authenticate(null, creds)).blockingFirst()

        then: //The last error is returned
        rsp instanceof AuthenticationFailed
        rsp.message.get() == "failed"
    }

    void "test authentication strategy multiple successes"() {
        given:
        def providers = [
                Stub(AuthenticationProvider) {
                    authenticate(_, _) >> create({ emitter ->
                        emitter.onNext(AuthenticationResponse.build("a", new TokenConfiguration() {}))
                        emitter.onComplete()
                    }, BackpressureStrategy.ERROR)
                },
                Stub(AuthenticationProvider) {
                    authenticate(_, _) >> create({ emitter ->
                        emitter.onNext(AuthenticationResponse.build("b", new TokenConfiguration() {}))
                        emitter.onComplete()
                    }, BackpressureStrategy.ERROR)
                },
        ]
        Authenticator authenticator = new Authenticator(providers, ALL)

        when:
        def creds = new UsernamePasswordCredentials('admin', 'admin')
        AuthenticationResponse rsp = Flowable.fromPublisher(authenticator.authenticate(null, creds)).blockingFirst()

        then: //The last error is returned
        rsp.authentication
        rsp.authentication.isPresent()
        rsp.authentication.get().name == "b"
    }
}
