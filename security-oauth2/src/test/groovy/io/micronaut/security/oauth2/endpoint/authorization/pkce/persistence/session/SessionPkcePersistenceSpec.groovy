package io.micronaut.security.oauth2.endpoint.authorization.pkce.persistence.session

import io.micronaut.core.util.StringUtils
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.security.oauth2.endpoint.authorization.pkce.Pkce
import io.micronaut.security.oauth2.endpoint.authorization.pkce.persistence.PkcePersistence
import io.micronaut.security.oauth2.endpoint.authorization.state.DefaultState
import io.micronaut.security.oauth2.endpoint.authorization.state.State
import io.micronaut.security.oauth2.endpoint.authorization.state.StateFactory
import io.micronaut.security.oauth2.endpoint.authorization.state.persistence.StateKeyedSessionValues
import io.micronaut.security.testutils.ApplicationContextSpecification
import io.micronaut.session.SessionStore
import io.micronaut.session.http.SessionForRequest

class SessionPkcePersistenceSpec extends ApplicationContextSpecification {

    @Override
    Map<String, Object> getLoginModeCookie() {
        ['micronaut.security.authentication': 'session']
    }

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.oauth2.pkce.persistence': 'session',
                'micronaut.security.oauth2.pkce.enabled': StringUtils.TRUE
        ]
    }

    void "PKCEPersistence is an instance of SessionPKCEPersistence"() {
        expect:
        applicationContext.containsBean(PkcePersistence)
        applicationContext.getBean(PkcePersistence) instanceof SessionPkcePersistence
    }

    void "code verifiers of several in-flight login flows coexist in the same session, keyed by the state of the flow"() {
        given:
        PkcePersistence persistence = applicationContext.getBean(PkcePersistence)
        HttpRequest<?> request = HttpRequest.GET('/oauth/login/foo')
        SessionForRequest.create(applicationContext.getBean(SessionStore), request)
        State first = new DefaultState()
        State second = new DefaultState()

        when: 'two login flows are started in the same session'
        persistence.persistPkce(loginRequest(request, first), HttpResponse.ok(), pkce('first'))
        persistence.persistPkce(loginRequest(request, second), HttpResponse.ok(), pkce('second'))

        then: 'the callback of the first flow receives the code verifier of the first flow'
        persistence.retrieveCodeVerifier(request, callbackState(first)).orElse(null) == 'first'
        !persistence.retrieveCodeVerifier(request, callbackState(first)).isPresent()

        and: 'the callback of the second flow receives the code verifier of the second flow'
        persistence.retrieveCodeVerifier(request, callbackState(second)).orElse(null) == 'second'
        !persistence.retrieveCodeVerifier(request, callbackState(second)).isPresent()
    }

    void "a code verifier persisted without a state is retrieved regardless of the callback state"() {
        given:
        PkcePersistence persistence = applicationContext.getBean(PkcePersistence)
        HttpRequest<?> request = HttpRequest.GET('/oauth/login/foo')
        SessionForRequest.create(applicationContext.getBean(SessionStore), request)

        when:
        persistence.persistPkce(request, HttpResponse.ok(), pkce('verifier'))

        then:
        persistence.retrieveCodeVerifier(request, new DefaultState()).orElse(null) == 'verifier'
        !persistence.retrieveCodeVerifier(request).isPresent()
    }

    void "starting more flows than the bound evicts the oldest code verifier"() {
        given:
        PkcePersistence persistence = applicationContext.getBean(PkcePersistence)
        HttpRequest<?> request = HttpRequest.GET('/oauth/login/foo')
        SessionForRequest.create(applicationContext.getBean(SessionStore), request)
        List<State> states = (1..(StateKeyedSessionValues.MAX_ENTRIES + 1)).collect { new DefaultState() }

        when:
        states.each { persistence.persistPkce(loginRequest(request, it), HttpResponse.ok(), pkce(it.nonce)) }

        then:
        !persistence.retrieveCodeVerifier(request, callbackState(states.first())).isPresent()
        states.drop(1).every { persistence.retrieveCodeVerifier(request, callbackState(it)).orElse(null) == it.nonce }
    }

    private static HttpRequest<?> loginRequest(HttpRequest<?> request, State state) {
        request.setAttribute(StateFactory.REQUEST_ATTRIBUTE_STATE, state)
        request
    }

    private static Pkce pkce(String codeVerifier) {
        new Pkce('S256', 'challenge-' + codeVerifier, codeVerifier)
    }

    private static State callbackState(State persisted) {
        DefaultState state = new DefaultState()
        state.nonce = persisted.nonce
        state
    }
}
