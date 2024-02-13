package io.micronaut.security.authentication

import groovy.transform.AutoImplement
import io.micronaut.context.ApplicationContext
import io.micronaut.security.authentication.provider.ReactiveAuthenticationProvider
import io.micronaut.security.config.AuthenticationStrategy
import io.micronaut.security.config.SecurityConfiguration
import io.micronaut.security.config.SecurityConfigurationProperties
import reactor.core.publisher.Flux
import reactor.core.publisher.FluxSink
import reactor.core.publisher.Mono
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

    void "if no authentication providers return empty optional"() {
        given:
        Authenticator authenticator = new Authenticator([], new SecurityConfigurationProperties())

        when:
        def creds = new UsernamePasswordCredentials('admin', 'admin')
        Optional<AuthenticationResponse> rsp = Mono.from(authenticator.authenticate(null, creds)).blockOptional()

        then:
        !rsp.isPresent()
    }

    void "if any authentication provider throws exception, continue with authentication"() {
        given:
        ApplicationContext ctx = ApplicationContext.run()
        def authProviderExceptionRaiser = Stub(ReactiveAuthenticationProvider) {
            authenticate(_, _) >> { Flux.error( new Exception('Authentication provider raised exception') ) }
        }
        def authProviderOK = Stub(ReactiveAuthenticationProvider) {
            authenticate(_, _) >> Flux.create({emitter ->
                emitter.next(AuthenticationResponse.success("admin"))
                emitter.complete()
            }, FluxSink.OverflowStrategy.ERROR)
        }
        Authenticator authenticator = new Authenticator(ctx, [authProviderExceptionRaiser, authProviderOK], [], new SecurityConfigurationProperties())

        when:
        def creds = new UsernamePasswordCredentials('admin', 'admin')
        Flux<AuthenticationResponse> rsp = Flux.from(authenticator.authenticate(null, creds))

        then:
        rsp.blockFirst() instanceof AuthenticationResponse
        rsp.blockFirst().isAuthenticated()

        cleanup:
        ctx.close()
    }

    void "if no authentication provider can authentication, the last error is sent back"() {
        given:
        ApplicationContext ctx = ApplicationContext.run()

        def authProviderFailed = Stub(ReactiveAuthenticationProvider) {
            authenticate(_, _) >> Flux.create({ emitter ->
                emitter.error(AuthenticationResponse.exception())
            }, FluxSink.OverflowStrategy.ERROR)
        }
        Authenticator authenticator = new Authenticator(ctx, [authProviderFailed], [], new SecurityConfigurationProperties())

        when:
        UsernamePasswordCredentials creds = new UsernamePasswordCredentials('admin', 'admin')
        Flux<AuthenticationResponse> rsp = Flux.from(authenticator.authenticate(null, creds))

        then:
        rsp.blockFirst() instanceof AuthenticationFailed

        cleanup:
        ctx.close()
    }

    void "test authentication strategy all with error and empty"() {
        given:
        ApplicationContext ctx = ApplicationContext.run()
        def providers = [
                Stub(ReactiveAuthenticationProvider) {
                    authenticate(_, _) >> Flux.create({ emitter ->
                        emitter.error(AuthenticationResponse.exception("failed"))
                    }, FluxSink.OverflowStrategy.ERROR)
                },
                Stub(ReactiveAuthenticationProvider) {
                    authenticate(_, _) >> Flux.empty()
                },
                Stub(ReactiveAuthenticationProvider) {
                    authenticate(_, _) >> Flux.create({ emitter ->
                        emitter.next(AuthenticationResponse.success("a"))
                        emitter.complete()
                    }, FluxSink.OverflowStrategy.ERROR)
                },
        ]
        Authenticator authenticator = new Authenticator(ctx, providers, [], ALL)

        when:
        def creds = new UsernamePasswordCredentials('admin', 'admin')
        AuthenticationResponse rsp = Flux.from(authenticator.authenticate(null, creds)).blockFirst()

        then: //The last error is returned
        rsp instanceof AuthenticationFailed
        rsp.message.get() == "Provider did not respond. Authentication rejected"

        cleanup:
        ctx.close()
    }

    void "test authentication strategy all with error"() {
        given:
        ApplicationContext ctx = ApplicationContext.run()

        def providers = [
                Stub(ReactiveAuthenticationProvider) {
                    authenticate(_, _) >>  Flux.create({ emitter ->
                        emitter.error(AuthenticationResponse.exception("failed"))
                    }, FluxSink.OverflowStrategy.ERROR)
                },
                Stub(ReactiveAuthenticationProvider) {
                    authenticate(_, _) >>  Flux.create({ emitter ->
                        emitter.next(AuthenticationResponse.success("a"))
                        emitter.complete()
                    }, FluxSink.OverflowStrategy.ERROR)
                },
        ]
        Authenticator authenticator = new Authenticator(ctx, providers, [], ALL)

        when:
        def creds = new UsernamePasswordCredentials('admin', 'admin')
        AuthenticationResponse rsp = Flux.from(authenticator.authenticate(null, creds)).blockFirst()

        then: //The last error is returned
        rsp instanceof AuthenticationFailed
        rsp.message.get() == "failed"

        cleanup:
        ctx.close()
    }

    void "test authentication strategy success first"() {
        given:
        ApplicationContext ctx = ApplicationContext.run()
        def providers = [
                Stub(ReactiveAuthenticationProvider) {
                    authenticate(_, _) >> Flux.create({ emitter ->
                        emitter.next(AuthenticationResponse.success("a"))
                        emitter.complete()
                    }, FluxSink.OverflowStrategy.ERROR)
                },
                Stub(ReactiveAuthenticationProvider) {
                    authenticate(_, _) >> Flux.create({ emitter ->
                        emitter.error(AuthenticationResponse.exception("failed"))
                    }, FluxSink.OverflowStrategy.ERROR)
                },
        ]
        Authenticator authenticator = new Authenticator(ctx, providers, [], ALL)

        when:
        def creds = new UsernamePasswordCredentials('admin', 'admin')
        AuthenticationResponse rsp = Flux.from(authenticator.authenticate(null, creds)).blockFirst()

        then: //The last error is returned
        rsp instanceof AuthenticationFailed
        rsp.message.get() == "failed"

        cleanup:
        ctx.close()
    }

    void "test authentication strategy multiple successes"() {
        given:
        ApplicationContext ctx = ApplicationContext.run()
        def providers = [
                Stub(ReactiveAuthenticationProvider) {
                    authenticate(_, _) >> Flux.create({ emitter ->
                        emitter.next(AuthenticationResponse.success("a"))
                        emitter.complete()
                    }, FluxSink.OverflowStrategy.ERROR)
                },
                Stub(ReactiveAuthenticationProvider) {
                    authenticate(_, _) >> Flux.create({ emitter ->
                        emitter.next(AuthenticationResponse.success("b"))
                        emitter.complete()
                    }, FluxSink.OverflowStrategy.ERROR)
                },
        ]
        Authenticator authenticator = new Authenticator(ctx, providers, [], ALL)

        when:
        def creds = new UsernamePasswordCredentials('admin', 'admin')
        AuthenticationResponse rsp = Flux.from(authenticator.authenticate(null, creds)).blockFirst()

        then: //The last error is returned
        rsp.authentication
        rsp.authentication.isPresent()
        rsp.authentication.get().name == "b"


        cleanup:
        ctx.close()
    }
}
