package io.micronaut.security.session

import io.micronaut.context.ApplicationContext
import io.micronaut.context.env.Environment
import io.micronaut.context.exceptions.NoSuchBeanException
import io.micronaut.http.server.exceptions.ExceptionHandler
import io.micronaut.inject.qualifiers.Qualifiers
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.authentication.AuthenticationException
import io.micronaut.security.authentication.AuthorizationException
import spock.lang.Shared
import spock.lang.Specification

class RejectionHandlerResolutionSpec extends Specification {

    static final SPEC_NAME_PROPERTY = 'spec.name'


    void "RedirectRejectionHandler is the default rejection handler resolved"() {
        EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer, [:], Environment.TEST)
        ApplicationContext context = embeddedServer.applicationContext

        when:
        context.getBean(ExtendedSessionSecurityfilterRejectionHandler)

        then:
        thrown(NoSuchBeanException)

        when:
        ExceptionHandler exceptionHandler = context.getBean(ExceptionHandler, Qualifiers.byTypeArgumentsClosest(AuthorizationException, Object))

        then:
        noExceptionThrown()
        exceptionHandler instanceof RedirectingAuthorizationExceptionHandler

        cleanup:
        context.close()

        and:
        embeddedServer.close()
    }

    void "If a bean extended SessionSecurityfilterRejectionHandler that is used as Rejection Handler"() {
        given:
        Map<String, Object> conf = [
                (SPEC_NAME_PROPERTY): getClass().simpleName,
        ]
        EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer, conf, Environment.TEST)
        ApplicationContext context = embeddedServer.applicationContext

        when:
        context.getBean(ExtendedSessionSecurityfilterRejectionHandler)

        then:
        noExceptionThrown()

        when:
        ExceptionHandler exceptionHandler = context.getBean(ExceptionHandler, Qualifiers.byTypeArgumentsClosest(AuthorizationException, Object))

        then:
        noExceptionThrown()
        exceptionHandler instanceof ExtendedSessionSecurityfilterRejectionHandler

        cleanup:
        context.close()

        and:
        embeddedServer.close()
    }
}
