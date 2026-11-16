package io.micronaut.security.oauth2.endpoint.nonce.persistence.session

import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.security.oauth2.endpoint.authorization.state.DefaultState
import io.micronaut.security.oauth2.endpoint.authorization.state.State
import io.micronaut.security.oauth2.endpoint.authorization.state.StateFactory
import io.micronaut.security.oauth2.endpoint.authorization.state.persistence.StateKeyedSessionValues
import io.micronaut.security.oauth2.endpoint.nonce.persistence.NoncePersistence
import io.micronaut.security.testutils.ApplicationContextSpecification
import io.micronaut.session.SessionStore
import io.micronaut.session.http.SessionForRequest

class SessionNoncePersistenceSpec extends ApplicationContextSpecification {

    @Override
    Map<String, Object> getLoginModeCookie() {
        ['micronaut.security.authentication': 'session']
    }

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.oauth2.openid.nonce.persistence': 'session'
        ]
    }

    void "NoncePersistence is an instance of SessionNoncePersistence"() {
        expect:
        applicationContext.containsBean(NoncePersistence)
        applicationContext.getBean(NoncePersistence) instanceof SessionNoncePersistence
    }

    void "nonces of several in-flight login flows coexist in the same session, keyed by the state of the flow"() {
        given:
        NoncePersistence persistence = applicationContext.getBean(NoncePersistence)
        HttpRequest<?> request = HttpRequest.GET('/oauth/login/foo')
        SessionForRequest.create(applicationContext.getBean(SessionStore), request)
        State first = new DefaultState()
        State second = new DefaultState()

        when: 'two login flows are started in the same session'
        persistence.persistNonce(loginRequest(request, first), HttpResponse.ok(), 'first')
        persistence.persistNonce(loginRequest(request, second), HttpResponse.ok(), 'second')

        then: 'the callback of the first flow receives the nonce of the first flow'
        persistence.retrieveNonce(request, callbackState(first)).orElse(null) == 'first'
        !persistence.retrieveNonce(request, callbackState(first)).isPresent()

        and: 'the callback of the second flow receives the nonce of the second flow'
        persistence.retrieveNonce(request, callbackState(second)).orElse(null) == 'second'
        !persistence.retrieveNonce(request, callbackState(second)).isPresent()
    }

    void "a nonce persisted without a state is retrieved regardless of the callback state"() {
        given:
        NoncePersistence persistence = applicationContext.getBean(NoncePersistence)
        HttpRequest<?> request = HttpRequest.GET('/oauth/login/foo')
        SessionForRequest.create(applicationContext.getBean(SessionStore), request)

        when:
        persistence.persistNonce(request, HttpResponse.ok(), 'nonce')

        then:
        persistence.retrieveNonce(request, new DefaultState()).orElse(null) == 'nonce'
        !persistence.retrieveNonce(request).isPresent()
    }

    void "starting more flows than the bound evicts the oldest nonce"() {
        given:
        NoncePersistence persistence = applicationContext.getBean(NoncePersistence)
        HttpRequest<?> request = HttpRequest.GET('/oauth/login/foo')
        SessionForRequest.create(applicationContext.getBean(SessionStore), request)
        List<State> states = (1..(StateKeyedSessionValues.MAX_ENTRIES + 1)).collect { new DefaultState() }

        when:
        states.each { persistence.persistNonce(loginRequest(request, it), HttpResponse.ok(), it.nonce) }

        then:
        !persistence.retrieveNonce(request, callbackState(states.first())).isPresent()
        states.drop(1).every { persistence.retrieveNonce(request, callbackState(it)).orElse(null) == it.nonce }
    }

    private static HttpRequest<?> loginRequest(HttpRequest<?> request, State state) {
        request.setAttribute(StateFactory.REQUEST_ATTRIBUTE_STATE, state)
        request
    }

    private static State callbackState(State persisted) {
        DefaultState state = new DefaultState()
        state.nonce = persisted.nonce
        state
    }
}
