package io.micronaut.security.oauth2.endpoint.authorization.response

import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.PlainJWT
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.oauth2.client.OpenIdProviderMetadata
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration
import io.micronaut.security.oauth2.endpoint.SecureEndpoint
import io.micronaut.security.oauth2.endpoint.token.request.TokenEndpointClient
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdAuthenticationMapper
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdTokenResponse
import io.micronaut.security.oauth2.endpoint.token.response.validation.ReactiveOpenIdTokenResponseValidator
import io.micronaut.security.oauth2.url.OauthRouteUrlBuilder
import reactor.core.publisher.Mono
import reactor.core.scheduler.Scheduler
import spock.lang.AutoCleanup
import spock.lang.Specification

import java.lang.reflect.Field
import java.lang.reflect.Modifier
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

class DefaultOpenIdAuthorizationResponseHandlerSchedulerSpec extends Specification {

    private static final String BLOCKING_THREAD_PREFIX = "test-blocking-"

    @AutoCleanup("shutdownNow")
    ExecutorService blockingExecutor = Executors.newCachedThreadPool({ Runnable r ->
        new Thread(r, BLOCKING_THREAD_PREFIX + UUID.randomUUID())
    })

    void "the blocking scheduler is created once and reused across callbacks"() {
        given:
        List<String> mapperThreads = Collections.synchronizedList([])
        OpenIdAuthenticationMapper mapper = { providerName, tokenResponse, claims, state ->
            mapperThreads << Thread.currentThread().name
            Mono.just(AuthenticationResponse.success("sherlock"))
        } as OpenIdAuthenticationMapper
        DefaultOpenIdAuthorizationResponseHandler<?> handler = createHandler(mapper)
        Field schedulerField = schedulerField()

        expect: 'the scheduler is held in a final field initialised by the constructor, and no raw executor is kept'
        Modifier.isFinal(schedulerField.modifiers)
        !DefaultOpenIdAuthorizationResponseHandler.declaredFields.any { !Modifier.isStatic(it.modifiers) && ExecutorService.isAssignableFrom(it.type) }

        when:
        Scheduler before = schedulerField.get(handler) as Scheduler
        AuthenticationResponse first = callback(handler)
        AuthenticationResponse second = callback(handler)
        Scheduler after = schedulerField.get(handler) as Scheduler

        then: 'both callbacks succeed and the same scheduler instance is reused'
        first.authenticated
        second.authenticated
        before != null
        before.is(after)

        and: 'the authentication mapper, a user extension point which may block, still runs on the blocking executor'
        mapperThreads.size() == 2
        mapperThreads.every { it.startsWith(BLOCKING_THREAD_PREFIX) }
    }

    private DefaultOpenIdAuthorizationResponseHandler<?> createHandler(OpenIdAuthenticationMapper mapper) {
        TokenEndpointClient tokenEndpointClient = Stub() {
            sendRequest(_) >> { Mono.just(new OpenIdTokenResponse(idToken: "id-token")) }
        }
        ReactiveOpenIdTokenResponseValidator validator = Stub() {
            validate(_, _, _, _) >> { Mono.just(new PlainJWT(new JWTClaimsSet.Builder().subject("sherlock").build())) }
        }
        new DefaultOpenIdAuthorizationResponseHandler<>(validator,
                mapper,
                tokenEndpointClient,
                Stub(OauthRouteUrlBuilder),
                null,
                null,
                blockingExecutor)
    }

    private static Field schedulerField() {
        List<Field> fields = DefaultOpenIdAuthorizationResponseHandler.declaredFields.findAll { Scheduler.isAssignableFrom(it.type) }
        assert fields.size() == 1
        Field field = fields.first()
        field.accessible = true
        field
    }

    private AuthenticationResponse callback(DefaultOpenIdAuthorizationResponseHandler<?> handler) {
        OpenIdAuthorizationResponse authorizationResponse = Stub() {
            getNonce() >> "nonce"
        }
        OauthClientConfiguration clientConfiguration = Stub() {
            getName() >> "test"
            getOpenid() >> Optional.empty()
        }
        Mono.from(handler.handle(authorizationResponse,
                clientConfiguration,
                Stub(OpenIdProviderMetadata),
                null,
                Stub(SecureEndpoint))).block()
    }
}
