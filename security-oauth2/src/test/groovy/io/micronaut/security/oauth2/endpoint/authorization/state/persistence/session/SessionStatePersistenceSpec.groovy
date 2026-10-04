package io.micronaut.security.oauth2.endpoint.authorization.state.persistence.session

import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.security.oauth2.endpoint.authorization.state.DefaultState
import io.micronaut.security.oauth2.endpoint.authorization.state.State
import io.micronaut.security.oauth2.endpoint.authorization.state.persistence.StateKeyedSessionValues
import io.micronaut.security.oauth2.endpoint.authorization.state.persistence.StatePersistence
import io.micronaut.security.testutils.ApplicationContextSpecification
import io.micronaut.session.Session
import io.micronaut.session.SessionStore
import io.micronaut.session.http.SessionForRequest

class SessionStatePersistenceSpec extends ApplicationContextSpecification {

    @Override
    Map<String, Object> getLoginModeCookie() {
        ['micronaut.security.authentication': 'session']
    }

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.oauth2.state.persistence': 'session'
        ]
    }

    void "StatePersistence is an instance of SessionStatePersistence"() {
        expect:
        applicationContext.containsBean(StatePersistence)
        applicationContext.getBean(StatePersistence) instanceof SessionStatePersistence
    }

    void "several in-flight states coexist in the same session and are retrieved by the callback state"() {
        given:
        StatePersistence persistence = applicationContext.getBean(StatePersistence)
        HttpRequest<?> request = HttpRequest.GET('/oauth/login/foo')
        Session session = SessionForRequest.create(applicationContext.getBean(SessionStore), request)
        State first = new DefaultState()
        State second = new DefaultState()

        when: 'two login flows are started in the same session'
        persistence.persistState(request, HttpResponse.ok(), first)
        persistence.persistState(request, HttpResponse.ok(), second)

        then: 'the first flow can be completed with its own state'
        persistence.retrieveState(request, callbackState(first)).map(State::getNonce).orElse(null) == first.nonce

        and: 'the state is consumed'
        !persistence.retrieveState(request, callbackState(first)).isPresent()

        and: 'the second flow can still be completed with its own state'
        persistence.retrieveState(request, callbackState(second)).map(State::getNonce).orElse(null) == second.nonce
        !session.get('oauth2State').isPresent()
    }

    void "retrieving with an unknown state does not consume other in-flight states"() {
        given:
        StatePersistence persistence = applicationContext.getBean(StatePersistence)
        HttpRequest<?> request = HttpRequest.GET('/oauth/login/foo')
        SessionForRequest.create(applicationContext.getBean(SessionStore), request)
        State first = new DefaultState()

        when:
        persistence.persistState(request, HttpResponse.ok(), first)

        then:
        !persistence.retrieveState(request, new DefaultState()).isPresent()
        persistence.retrieveState(request, callbackState(first)).isPresent()
    }

    void "retrieving without a callback state returns the most recent in-flight state"() {
        given:
        StatePersistence persistence = applicationContext.getBean(StatePersistence)
        HttpRequest<?> request = HttpRequest.GET('/oauth/login/foo')
        SessionForRequest.create(applicationContext.getBean(SessionStore), request)
        State first = new DefaultState()
        State second = new DefaultState()

        when:
        persistence.persistState(request, HttpResponse.ok(), first)
        persistence.persistState(request, HttpResponse.ok(), second)

        then:
        persistence.retrieveState(request).map(State::getNonce).orElse(null) == second.nonce
        persistence.retrieveState(request).map(State::getNonce).orElse(null) == first.nonce
        !persistence.retrieveState(request).isPresent()
    }

    void "starting more flows than the bound evicts the oldest state"() {
        given:
        StatePersistence persistence = applicationContext.getBean(StatePersistence)
        HttpRequest<?> request = HttpRequest.GET('/oauth/login/foo')
        SessionForRequest.create(applicationContext.getBean(SessionStore), request)
        List<State> states = (1..(StateKeyedSessionValues.MAX_ENTRIES + 1)).collect { new DefaultState() }

        when:
        states.each { persistence.persistState(request, HttpResponse.ok(), it) }

        then: 'the oldest state was evicted'
        !persistence.retrieveState(request, callbackState(states.first())).isPresent()

        and: 'the remaining states are still available'
        states.drop(1).every { persistence.retrieveState(request, callbackState(it)).isPresent() }
    }

    private static State callbackState(State persisted) {
        DefaultState state = new DefaultState()
        state.nonce = persisted.nonce
        state
    }
}
