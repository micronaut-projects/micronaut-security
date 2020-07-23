package io.micronaut.security

import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.client.RxHttpClient
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.management.endpoint.health.HealthLevelOfDetail
import io.micronaut.management.health.indicator.HealthResult
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.authentication.AuthenticationException
import io.micronaut.security.authentication.AuthenticationFailed
import io.micronaut.security.authentication.AuthenticationProvider
import io.micronaut.security.authentication.AuthenticationRequest
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.authentication.UserDetails
import io.reactivex.BackpressureStrategy
import io.reactivex.Flowable
import io.reactivex.annotations.NonNull
import io.reactivex.functions.Function
import org.reactivestreams.Publisher
import spock.lang.Specification
import spock.lang.Unroll

import javax.inject.Singleton

class HealthSensitivitySpec extends Specification {

    @Unroll
    void "If endpoints.health.sensitive=true #description => 401"(Boolean security, String description) {
        given:
        Map m = [
                'spec.name'                            : 'healthsensitivity',
                'endpoints.health.enabled'             : true,
                'endpoints.health.disk-space.threshold': '9999GB',
                'endpoints.health.sensitive'           : true,
        ]
        if (security != null) {
            m['micronaut.security.enabled'] = security
        }

        EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer, m)
        URL server = embeddedServer.getURL()
        RxHttpClient rxClient = embeddedServer.applicationContext.createBean(RxHttpClient, server)

        when:
        HttpRequest httpRequest = HttpRequest.GET("/health")
        rxClient.exchange(httpRequest, Map).blockingFirst()

        then:
        def e = thrown(HttpClientResponseException)
        e.status == HttpStatus.UNAUTHORIZED

        cleanup:
        embeddedServer.close()
        rxClient.close()

        where:
        security << [null, true, false]
        description = security == null ? 'with default security enabled' : (security ? 'with security but unauthenticated' : 'without security')
    }

    @Unroll
    void "test #description #expected"(boolean sensitive, boolean security, boolean authenticated, HealthLevelOfDetail expected, String description) {
        given:
        Map m = [
                'spec.name'                            : 'healthsensitivity',
                'endpoints.health.enabled'             : true,
                'endpoints.health.sensitive'           : sensitive,
                'endpoints.health.disk-space.threshold': '9999GB',
        ]
        if (security) {
            m['micronaut.security.enabled'] = security
        }

        EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer, m)
        URL server = embeddedServer.getURL()
        RxHttpClient rxClient = embeddedServer.applicationContext.createBean(RxHttpClient, server)

        when:
        HttpRequest httpRequest = HttpRequest.GET("/health")
        if (authenticated) {
            httpRequest = httpRequest.basicAuth("user", "password")
        }
        def response = rxClient.exchange(httpRequest, Map)
        .onErrorResumeNext(new Function<Throwable, Publisher<? extends HttpResponse<HealthResult>>>() {
            @Override
            Publisher<? extends HttpResponse<HealthResult>> apply(@NonNull Throwable throwable) throws Exception {

                HttpResponse<?> httpResponse = ((HttpClientResponseException) throwable).response
                httpResponse.getBody(Map)
                return Flowable.just(httpResponse)
            }
        }).blockingFirst()
        Map result = response.getBody(Map).get()

        then:
        response.code() == HttpStatus.SERVICE_UNAVAILABLE.code
        result.status == "DOWN"
        if (expected == HealthLevelOfDetail.STATUS_DESCRIPTION_DETAILS) {
            assert result.containsKey('details')
            assert result.details.diskSpace.status == "DOWN"
            assert result.details.diskSpace.details.error.startsWith("Free disk space below threshold.")
        } else {
            assert !result.containsKey('details')
        }

        cleanup:
        embeddedServer.close()
        rxClient.close()

        where:
        sensitive | security | authenticated | expected
        true      | true     | true          | HealthLevelOfDetail.STATUS_DESCRIPTION_DETAILS
        false     | true     | false         | HealthLevelOfDetail.STATUS
        false     | true     | true          | HealthLevelOfDetail.STATUS_DESCRIPTION_DETAILS
        false     | false    | false         | HealthLevelOfDetail.STATUS

        description = "endpoints.health.sensitive=${sensitive} " + (security ? 'micronaut.security.enabled=true ' + (authenticated ? 'authenticated' : 'not authenticated') : '')
    }

    void "test details visible AUTHENTICATED"() {
        given:
        EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer, [
            'spec.name'                            : 'healthsensitivity',
            'endpoints.health.enabled'             : true,
            'endpoints.health.sensitive'           : false,
            'endpoints.health.detailsVisible'      : 'AUTHENTICATED'])
        URL server = embeddedServer.getURL()
        RxHttpClient rxClient = embeddedServer.applicationContext.createBean(RxHttpClient, server)

        when:
        HttpRequest httpRequest = HttpRequest.GET("/health")
        HttpResponse response = rxClient.exchange(httpRequest, Map).blockingFirst()
        Map result = response.body()

        then: // The details are not included because the user is not authenticated
        response.code() == HttpStatus.OK.code
        result.containsKey('status')
        !result.containsKey('details')


        when:
        httpRequest = HttpRequest.GET("/health").basicAuth("user", "password")
        response = rxClient.exchange(httpRequest, Map).blockingFirst()
        result = response.body()

        then: // The details are included because the user is authenticated
        response.code() == HttpStatus.OK.code
        result.containsKey('status')
        result.containsKey('details')

        cleanup:
        embeddedServer.close()
        rxClient.close()
    }

    void "test details visible ANONYMOUS"() {
        given:
        EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer, [
                'spec.name'                            : 'healthsensitivity',
                'endpoints.health.enabled'             : true,
                'endpoints.health.sensitive'           : false,
                'endpoints.health.detailsVisible'      : 'ANONYMOUS'])
        URL server = embeddedServer.getURL()
        RxHttpClient rxClient = embeddedServer.applicationContext.createBean(RxHttpClient, server)

        when:
        HttpRequest httpRequest = HttpRequest.GET("/health")
        HttpResponse response = rxClient.exchange(httpRequest, Map).blockingFirst()
        Map result = response.body()

        then: // The details are included because detailsVisible is ANONYMOUS
        response.code() == HttpStatus.OK.code
        result.containsKey('status')
        result.containsKey('details')

        cleanup:
        embeddedServer.close()
        rxClient.close()
    }


    void "test details visible NEVER"() {
        given:
        EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer, [
                'spec.name'                            : 'healthsensitivity',
                'endpoints.health.enabled'             : true,
                'endpoints.health.sensitive'           : false,
                'endpoints.health.detailsVisible'      : 'NEVER'])
        URL server = embeddedServer.getURL()
        RxHttpClient rxClient = embeddedServer.applicationContext.createBean(RxHttpClient, server)

        when:
        HttpRequest httpRequest = HttpRequest.GET("/health").basicAuth("user", "password")
        HttpResponse response = rxClient.exchange(httpRequest, Map).blockingFirst()
        Map result = response.body()

        then: // The details are not included because detailsVisible is NEVER
        response.code() == HttpStatus.OK.code
        result.containsKey('status')
        !result.containsKey('details')

        cleanup:
        embeddedServer.close()
        rxClient.close()
    }

    @Singleton
    @Requires(property = 'spec.name', value = 'healthsensitivity')
    static class AuthenticationProviderUserPassword implements AuthenticationProvider {

        @Override
        Publisher<AuthenticationResponse> authenticate(HttpRequest<?> httpRequest, AuthenticationRequest<?, ?> authenticationRequest) {
            Flowable.create({emitter ->
                if ( authenticationRequest.identity == 'user' && authenticationRequest.secret == 'password' ) {
                    emitter.onNext(new UserDetails('user', []))
                    emitter.onComplete()
                } else {
                    emitter.onError(new AuthenticationException(new AuthenticationFailed()))
                }

            }, BackpressureStrategy.ERROR)
        }
    }
}
