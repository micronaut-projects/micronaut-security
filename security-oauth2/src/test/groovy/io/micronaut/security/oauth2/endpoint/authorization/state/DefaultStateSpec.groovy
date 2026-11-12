package io.micronaut.security.oauth2.endpoint.authorization.state

import io.micronaut.core.annotation.ReflectiveAccess
import io.micronaut.http.HttpRequest
import io.micronaut.http.MutableHttpResponse
import io.micronaut.security.oauth2.endpoint.authorization.state.persistence.StatePersistence
import spock.lang.Specification

class DefaultStateSpec extends Specification {

    void "DefaultState is annotated with ReflectiveAccess"() {
        expect:
        DefaultState.class.isAnnotationPresent(ReflectiveAccess)
    }

    void "DefaultState equality and hashCode are based on the nonce only"() {
        given:
        DefaultState a = new DefaultState(nonce: 'abc', redirectUri: URI.create('https://example.com/a'))
        DefaultState b = new DefaultState(nonce: 'abc', redirectUri: URI.create('https://example.com/b'))
        DefaultState c = new DefaultState(nonce: 'xyz', redirectUri: URI.create('https://example.com/a'))

        expect:
        a == b
        b == a
        a.hashCode() == b.hashCode()
        a != c
        c != a
    }

    void "setOriginalUri is a no-op and does not affect equality nor hashCode"() {
        given:
        DefaultState a = new DefaultState(nonce: 'abc')
        DefaultState b = new DefaultState(nonce: 'abc')

        when:
        a.setOriginalUri(URI.create('https://example.com/secured'))

        then:
        a == b
        a.hashCode() == b.hashCode()
    }

    void "DefaultStateFactory does not consult the request for an original URI"() {
        given:
        HttpRequest<?> request = Mock()
        MutableHttpResponse<?> response = Mock()
        StatePersistence statePersistence = Mock()
        StateSerDes stateSerDes = Mock()
        MutableState state = Mock()
        DefaultStateFactory factory = new DefaultStateFactory(stateSerDes, statePersistence) {
            @Override
            protected MutableState createInitialState() {
                return state
            }
        }

        when:
        String result = factory.buildState(request, response, null)

        then:
        1 * statePersistence.persistState(request, response, state)
        1 * request.setAttribute(StateFactory.REQUEST_ATTRIBUTE_STATE, state)
        1 * stateSerDes.serialize(state) >> 'serialized'
        0 * state.setOriginalUri(_)
        0 * request._

        and:
        result == 'serialized'
    }
}
