package io.micronaut.security.session

import ch.qos.logback.classic.Level
import ch.qos.logback.classic.Logger
import ch.qos.logback.classic.spi.ILoggingEvent
import ch.qos.logback.core.read.ListAppender
import io.micronaut.http.HttpHeaders
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpStatus
import io.micronaut.http.MutableHttpResponse
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.config.RedirectConfiguration
import io.micronaut.security.config.RedirectService
import io.micronaut.security.errors.PriorToLoginPersistence
import io.micronaut.security.filters.SecurityFilter
import io.micronaut.security.testutils.ApplicationContextSpecification
import io.micronaut.session.Session
import io.micronaut.session.SessionStore
import io.micronaut.session.http.HttpSessionFilter
import io.micronaut.session.http.HttpSessionIdEncoder
import io.micronaut.session.http.SessionForRequest
import org.slf4j.LoggerFactory

import java.util.concurrent.CompletableFuture

class SessionInvalidationSpec extends ApplicationContextSpecification {

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.authentication': 'session',
        ]
    }

    @Override
    String getSpecName() {
        'SessionInvalidationSpec'
    }

    void "login migrates the previous session even if the session store cannot delete it, log level #level"() {
        given:
        ListAppender<ILoggingEvent> appender = attachAppender(SessionLoginHandler, level)
        SessionStore<Session> sessionStore = new FailingDeleteSessionStore(getBean(SessionStore))
        SessionLoginHandler loginHandler = new SessionLoginHandler(getBean(RedirectConfiguration),
                sessionStore, null, getBean(RedirectService), [new DefaultSessionPopulator<>()])
        HttpRequest<?> request = HttpRequest.GET("/")
        Session previous = SessionForRequest.create(sessionStore, request)
        previous.put("visited", "true")

        when:
        MutableHttpResponse<?> response = loginHandler.loginSuccess(Authentication.build("sherlock"), request)
        Session session = SessionForRequest.find(request).get()

        then:
        response.status() == HttpStatus.SEE_OTHER
        session.id != previous.id
        session.get("visited", String).get() == "true"
        session.get(SecurityFilter.AUTHENTICATION).isPresent()
        sessionStore.deletedIds == [previous.id]
        appender.list*.formattedMessage == expectedMessages(level, "Could not delete the previous session ${previous.id} after authentication")

        cleanup:
        detachAppender(SessionLoginHandler, appender)

        where:
        level << [Level.WARN, Level.ERROR]
    }

    void "login redirects to the original URI saved prior to login"() {
        given:
        PriorToLoginPersistence<HttpRequest<?>, MutableHttpResponse<?>> priorToLoginPersistence = Stub() {
            getOriginalUri(_, _) >> Optional.of(URI.create("/original"))
        }
        SessionLoginHandler loginHandler = new SessionLoginHandler(getBean(RedirectConfiguration),
                getBean(SessionStore), priorToLoginPersistence, getBean(RedirectService), [new DefaultSessionPopulator<>()])

        when:
        MutableHttpResponse<?> response = loginHandler.loginSuccess(Authentication.build("sherlock"), HttpRequest.GET("/"))

        then:
        response.status() == HttpStatus.SEE_OTHER
        response.getHeaders().get(HttpHeaders.LOCATION) == "/original"
    }

    void "logout responds even if the session store cannot delete the session, log level #level"() {
        given:
        ListAppender<ILoggingEvent> appender = attachAppender(SessionLogoutHandler, level)
        SessionStore<Session> sessionStore = new FailingDeleteSessionStore(getBean(SessionStore))
        SessionLogoutHandler logoutHandler = new SessionLogoutHandler(getBean(RedirectConfiguration),
                getBean(RedirectService), sessionStore, getBeansOfType(HttpSessionIdEncoder) as List)
        HttpRequest<?> request = HttpRequest.GET("/")
        Session session = SessionForRequest.create(sessionStore, request)
        session.put(SecurityFilter.AUTHENTICATION, Authentication.build("sherlock"))

        when:
        MutableHttpResponse<?> response = logoutHandler.logout(request)

        then:
        response.status() == HttpStatus.SEE_OTHER
        !session.get(SecurityFilter.AUTHENTICATION).isPresent()
        session.isExpired()
        !request.getAttributes().contains(HttpSessionFilter.SESSION_ATTRIBUTE)
        sessionStore.deletedIds == [session.id]
        response.getHeaders().getAll("set-cookie").any { it.startsWith("SESSION=;") }
        appender.list*.formattedMessage == expectedMessages(level, "Could not delete session ${session.id} on logout")

        cleanup:
        detachAppender(SessionLogoutHandler, appender)

        where:
        level << [Level.WARN, Level.ERROR]
    }

    void "logout without a session store only removes the authentication from the session"() {
        given:
        SessionStore<Session> sessionStore = getBean(SessionStore)
        SessionLogoutHandler logoutHandler = new SessionLogoutHandler(getBean(RedirectConfiguration), getBean(RedirectService))
        HttpRequest<?> request = HttpRequest.GET("/")
        Session session = SessionForRequest.create(sessionStore, request)
        session.put(SecurityFilter.AUTHENTICATION, Authentication.build("sherlock"))

        when:
        MutableHttpResponse<?> response = logoutHandler.logout(request)

        then:
        response.status() == HttpStatus.SEE_OTHER
        !session.get(SecurityFilter.AUTHENTICATION).isPresent()
        !session.isExpired()
        SessionForRequest.find(request).isPresent()
        !response.getHeaders().contains("set-cookie")
    }

    void "logout without a session store responds with OK if redirection is disabled"() {
        given:
        RedirectConfiguration redirectConfiguration = Stub() {
            isEnabled() >> false
        }
        SessionLogoutHandler logoutHandler = new SessionLogoutHandler(redirectConfiguration, Stub(RedirectService))

        when:
        MutableHttpResponse<?> response = logoutHandler.logout(HttpRequest.GET("/"))

        then:
        response.status() == HttpStatus.OK
    }

    void "logout without a session responds without expiring a session identifier"() {
        given:
        SessionLogoutHandler logoutHandler = getBean(SessionLogoutHandler)

        when:
        MutableHttpResponse<?> response = logoutHandler.logout(HttpRequest.GET("/"))

        then:
        response.status() == HttpStatus.SEE_OTHER
        !response.getHeaders().contains("set-cookie")
    }

    private static ListAppender<ILoggingEvent> attachAppender(Class<?> loggerClass, Level level) {
        Logger logger = (Logger) LoggerFactory.getLogger(loggerClass)
        ListAppender<ILoggingEvent> appender = new ListAppender<>()
        appender.start()
        logger.addAppender(appender)
        logger.setLevel(level)
        appender
    }

    private static void detachAppender(Class<?> loggerClass, ListAppender<ILoggingEvent> appender) {
        Logger logger = (Logger) LoggerFactory.getLogger(loggerClass)
        logger.detachAppender(appender)
        logger.setLevel(null)
    }

    private static List<String> expectedMessages(Level level, String message) {
        level.isGreaterOrEqual(Level.ERROR) ? [] : [message]
    }

    static class FailingDeleteSessionStore implements SessionStore<Session> {

        private final SessionStore<Session> delegate

        final List<String> deletedIds = []

        FailingDeleteSessionStore(SessionStore<Session> delegate) {
            this.delegate = delegate
        }

        @Override
        Session newSession() {
            delegate.newSession()
        }

        @Override
        CompletableFuture<Optional<Session>> findSession(String id) {
            delegate.findSession(id)
        }

        @Override
        CompletableFuture<Boolean> deleteSession(String id) {
            deletedIds << id
            CompletableFuture.failedFuture(new IllegalStateException("session store unavailable"))
        }

        @Override
        CompletableFuture<Session> save(Session session) {
            delegate.save(session)
        }
    }
}
