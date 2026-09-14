package io.micronaut.security.token.jwt.endpoints

import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Requires
import io.micronaut.core.async.publisher.Publishers
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.client.BlockingHttpClient
import io.micronaut.http.client.HttpClient
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.scheduling.TaskExecutors
import io.micronaut.scheduling.annotation.Async
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.authentication.AuthenticationRequest
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.authentication.UsernamePasswordCredentials
import io.micronaut.security.authentication.provider.ReactiveAuthenticationProvider
import io.micronaut.security.token.event.RefreshTokenGeneratedEvent
import io.micronaut.security.token.refresh.RefreshTokenPersistence
import io.micronaut.security.token.render.BearerAccessRefreshToken
import jakarta.inject.Singleton
import org.reactivestreams.Publisher
import reactor.core.publisher.Mono
import spock.lang.Specification

import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit

/**
 * {@link RefreshTokenPersistence#persistToken(RefreshTokenGeneratedEvent)} is an {@code @EventListener}
 * invoked synchronously on the thread that completed authentication. For a reactive authentication provider
 * that is the Netty event loop, so blocking implementations must offload the work, e.g. with {@code @Async}.
 */
class RefreshTokenPersistenceThreadSpec extends Specification {

    private static final String INLINE = 'RefreshTokenPersistenceThreadSpecInline'
    private static final String OFFLOADED = 'RefreshTokenPersistenceThreadSpecOffloaded'

    void "without offloading, persistToken runs inline on the thread that emitted the authentication"() {
        given:
        EmbeddedServer server = startServer(INLINE)
        HttpClient httpClient = server.applicationContext.createBean(HttpClient, server.URL)
        BlockingHttpClient client = httpClient.toBlocking()

        when:
        HttpResponse<BearerAccessRefreshToken> rsp = login(client)

        then:
        rsp.status() == HttpStatus.OK
        rsp.body().refreshToken

        when:
        String providerThread = server.applicationContext.getBean(ThreadRecordingAuthenticationProvider).thread.get(5, TimeUnit.SECONDS)
        String persistenceThread = server.applicationContext.getBean(InlineRefreshTokenPersistence).thread.get(5, TimeUnit.SECONDS)

        then: 'the listener ran on the same (event loop) thread as the reactive authentication provider'
        persistenceThread == providerThread
        isEventLoop(persistenceThread)

        cleanup:
        httpClient?.close()
        server?.close()
    }

    void "@Async(TaskExecutors.BLOCKING) moves persistToken off the event loop"() {
        given:
        EmbeddedServer server = startServer(OFFLOADED)
        HttpClient httpClient = server.applicationContext.createBean(HttpClient, server.URL)
        BlockingHttpClient client = httpClient.toBlocking()

        when:
        HttpResponse<BearerAccessRefreshToken> rsp = login(client)

        then:
        rsp.status() == HttpStatus.OK
        rsp.body().refreshToken

        when:
        String providerThread = server.applicationContext.getBean(ThreadRecordingAuthenticationProvider).thread.get(5, TimeUnit.SECONDS)
        OffloadedRefreshTokenPersistence persistence = server.applicationContext.getBean(OffloadedRefreshTokenPersistence)
        String persistenceThread = persistence.thread.get(5, TimeUnit.SECONDS)

        then:
        isEventLoop(providerThread)
        !isEventLoop(persistenceThread)
        persistenceThread != providerThread
        persistence.tokens.size() == 1

        cleanup:
        httpClient?.close()
        server?.close()
    }

    private static EmbeddedServer startServer(String specName) {
        ApplicationContext.run(EmbeddedServer, [
                'spec.name': specName,
                'micronaut.security.authentication': 'bearer',
                'micronaut.security.token.jwt.signatures.secret.generator.secret': 'qrD6h8K6S9503Q06Y6Rfk21TErImPYqa',
                'micronaut.security.token.jwt.generator.refresh-token.secret': 'pleaseChangeThisSecretForANewOne',
        ] as Map<String, Object>)
    }

    private static HttpResponse<BearerAccessRefreshToken> login(BlockingHttpClient client) {
        client.exchange(HttpRequest.POST('/login', new UsernamePasswordCredentials('user', 'password')), BearerAccessRefreshToken)
    }

    private static boolean isEventLoop(String threadName) {
        threadName.contains('eventLoop') || threadName.contains('nioEventLoopGroup')
    }

    @Singleton
    @Requires(property = 'spec.name', pattern = 'RefreshTokenPersistenceThreadSpec.*')
    static class ThreadRecordingAuthenticationProvider<T> implements ReactiveAuthenticationProvider<T, String, String> {
        final CompletableFuture<String> thread = new CompletableFuture<>()

        @Override
        Publisher<AuthenticationResponse> authenticate(T requestContext, AuthenticationRequest<String, String> authenticationRequest) {
            Mono.fromCallable {
                thread.complete(Thread.currentThread().name)
                AuthenticationResponse.success(authenticationRequest.identity)
            }
        }
    }

    @Singleton
    @Requires(property = 'spec.name', value = INLINE)
    static class InlineRefreshTokenPersistence implements RefreshTokenPersistence {
        final CompletableFuture<String> thread = new CompletableFuture<>()

        @Override
        void persistToken(RefreshTokenGeneratedEvent event) {
            thread.complete(Thread.currentThread().name)
        }

        @Override
        Publisher<Authentication> getAuthentication(String refreshToken) {
            Publishers.empty()
        }
    }

    @Singleton
    @Requires(property = 'spec.name', value = OFFLOADED)
    static class OffloadedRefreshTokenPersistence implements RefreshTokenPersistence {
        final CompletableFuture<String> thread = new CompletableFuture<>()
        final Map<String, Authentication> tokens = new ConcurrentHashMap<>()

        @Async(TaskExecutors.BLOCKING)
        @Override
        void persistToken(RefreshTokenGeneratedEvent event) {
            tokens.put(event.refreshToken, event.authentication)
            thread.complete(Thread.currentThread().name)
        }

        @Override
        Publisher<Authentication> getAuthentication(String refreshToken) {
            Publishers.just(tokens.get(refreshToken))
        }
    }
}
