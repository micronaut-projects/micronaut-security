package io.micronaut.security.authentication

import groovy.transform.AutoImplement
import io.micronaut.security.config.AuthenticationStrategy
import io.micronaut.security.config.SecurityConfiguration
import io.micronaut.security.config.SecurityConfigurationProperties
import reactor.core.publisher.FluxSink
import reactor.core.publisher.Flux
import spock.lang.Ignore
import spock.lang.Shared
import spock.lang.Specification

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

    @Ignore
    void "if no authentication providers return empty optional"() {
        given:
        Authenticator authenticator = new Authenticator([], new SecurityConfigurationProperties())

        when:
        def creds = new UsernamePasswordCredentials('admin', 'admin')
        Flux<AuthenticationResponse> rsp = Flux.from(authenticator.authenticate(null, creds))
        rsp.blockFirst()

        then:
        thrown(NoSuchElementException)
    }

    void "if any authentication provider throws exception, continue with authentication"() {
        given:
        def authProviderExceptionRaiser = Stub(AuthenticationProvider) {
            authenticate(_, _) >> { Flux.error( new Exception('Authentication provider raised exception') ) }
        }
        def authProviderOK = Stub(AuthenticationProvider) {
            authenticate(_, _) >> Flux.create({emitter ->
                emitter.next(new UserDetails('admin', []))
                emitter.complete()
            }, FluxSink.OverflowStrategy.ERROR)
        }
        Authenticator authenticator = new Authenticator([authProviderExceptionRaiser, authProviderOK], new SecurityConfigurationProperties())

        when:
        def creds = new UsernamePasswordCredentials('admin', 'admin')
        Flux<AuthenticationResponse> rsp = authenticator.authenticate(null, creds)

        then:
        rsp.blockFirst() instanceof UserDetails
    }

    void "if no authentication provider can authentication, the last error is sent back"() {
        given:
        def authProviderFailed = Stub(AuthenticationProvider) {
            authenticate(_, _) >> Flux.create({ emitter ->
                emitter.error(new AuthenticationException(new AuthenticationFailed()))
            }, FluxSink.OverflowStrategy.ERROR)
        }
        Authenticator authenticator = new Authenticator([authProviderFailed], new SecurityConfigurationProperties())

        when:
        UsernamePasswordCredentials creds = new UsernamePasswordCredentials('admin', 'admin')
        Flux<AuthenticationResponse> rsp = Flux.from(authenticator.authenticate(null, creds))

        then:
        rsp.blockFirst() instanceof AuthenticationFailed
    }

    void "test authentication strategy all with error and empty"() {
        given:
        def providers = [
                Stub(AuthenticationProvider) {
                    authenticate(_, _) >> Flux.create({ emitter ->
                        emitter.error(new AuthenticationException(new AuthenticationFailed("failed")))
                    }, FluxSink.OverflowStrategy.ERROR)
                },
                Stub(AuthenticationProvider) {
                    authenticate(_, _) >> Flux.empty()
                },
                Stub(AuthenticationProvider) {
                    authenticate(_, _) >> Flux.create({ emitter ->
                        emitter.next(new UserDetails("a", []))
                        emitter.complete()
                    }, FluxSink.OverflowStrategy.ERROR)
                },
        ]
        Authenticator authenticator = new Authenticator(providers, ALL)

        when:
        def creds = new UsernamePasswordCredentials('admin', 'admin')
        AuthenticationResponse rsp = Flux.from(authenticator.authenticate(null, creds)).blockFirst()

        then: //The last error is returned
        rsp instanceof AuthenticationFailed
        rsp.message.get() == "Provider did not respond. Authentication rejected"
    }

    void "test authentication strategy all with error"() {
        given:
        def providers = [
                Stub(AuthenticationProvider) {
                    authenticate(_, _) >>  Flux.create({ emitter ->
                        emitter.error(new AuthenticationException(new AuthenticationFailed("failed")))
                    }, FluxSink.OverflowStrategy.ERROR)
                },
                Stub(AuthenticationProvider) {
                    authenticate(_, _) >>  Flux.create({ emitter ->
                        emitter.next(new UserDetails("a", []))
                        emitter.complete()
                    }, FluxSink.OverflowStrategy.ERROR)
                },
        ]
        Authenticator authenticator = new Authenticator(providers, ALL)

        when:
        def creds = new UsernamePasswordCredentials('admin', 'admin')
        AuthenticationResponse rsp = Flux.from(authenticator.authenticate(null, creds)).blockFirst()

        then: //The last error is returned
        rsp instanceof AuthenticationFailed
        rsp.message.get() == "failed"
    }

    void "test authentication strategy success first"() {
        given:
        def providers = [
                Stub(AuthenticationProvider) {
                    authenticate(_, _) >> Flux.create({ emitter ->
                        emitter.next(new UserDetails("a", []))
                        emitter.complete()
                    }, FluxSink.OverflowStrategy.ERROR)
                },
                Stub(AuthenticationProvider) {
                    authenticate(_, _) >> Flux.create({ emitter ->
                        emitter.error(new AuthenticationException(new AuthenticationFailed("failed")))
                    }, FluxSink.OverflowStrategy.ERROR)
                },
        ]
        Authenticator authenticator = new Authenticator(providers, ALL)

        when:
        def creds = new UsernamePasswordCredentials('admin', 'admin')
        AuthenticationResponse rsp = Flux.from(authenticator.authenticate(null, creds)).blockFirst()

        then: //The last error is returned
        rsp instanceof AuthenticationFailed
        rsp.message.get() == "failed"
    }

    void "test authentication strategy multiple successes"() {
        given:
        def providers = [
                Stub(AuthenticationProvider) {
                    authenticate(_, _) >> Flux.create({ emitter ->
                        emitter.next(new UserDetails("a", []))
                        emitter.complete()
                    }, FluxSink.OverflowStrategy.ERROR)
                },
                Stub(AuthenticationProvider) {
                    authenticate(_, _) >> Flux.create({ emitter ->
                        emitter.next(new UserDetails("b", []))
                        emitter.complete()
                    }, FluxSink.OverflowStrategy.ERROR)
                },
        ]
        Authenticator authenticator = new Authenticator(providers, ALL)

        when:
        def creds = new UsernamePasswordCredentials('admin', 'admin')
        AuthenticationResponse rsp = Flux.from(authenticator.authenticate(null, creds)).blockFirst()

        then: //The last error is returned
        rsp instanceof UserDetails
        ((UserDetails) rsp).username == "b"
    }
}
