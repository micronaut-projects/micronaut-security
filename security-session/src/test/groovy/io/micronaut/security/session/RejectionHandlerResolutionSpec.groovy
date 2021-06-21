package io.micronaut.security.session

import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Replaces
import io.micronaut.context.annotation.Requires
import io.micronaut.context.exceptions.NoSuchBeanException
import io.micronaut.http.HttpRequest
import io.micronaut.http.MutableHttpResponse
import io.micronaut.http.server.exceptions.ExceptionHandler
import io.micronaut.inject.qualifiers.Qualifiers
import io.micronaut.security.testutils.ApplicationContextSpecification
import io.micronaut.security.authentication.AuthorizationException
import io.micronaut.security.authentication.DefaultAuthorizationExceptionHandler

import javax.inject.Singleton

class RejectionHandlerResolutionSpec extends ApplicationContextSpecification {

    @Override
    String getSpecName() {
        'RejectionHandlerResolutionSpec'
    }

    void "RedirectRejectionHandler is the default rejection handler resolved"() {
        given:
        ApplicationContext ctx = ApplicationContext.run([:])

        when:
        ctx.getBean(ExtendedSessionSecurityfilterRejectionHandler)

        then:
        thrown(NoSuchBeanException)

        when:
        ExceptionHandler exceptionHandler = ctx.getBean(ExceptionHandler, Qualifiers.byTypeArgumentsClosest(AuthorizationException, Object))

        then:
        noExceptionThrown()
        exceptionHandler instanceof DefaultAuthorizationExceptionHandler

        cleanup:
        ctx.close()
    }

    void "If a bean extended DefaultAuthorizationExceptionHandler that is used as Rejection Handler"() {
        when:
        applicationContext.getBean(ExtendedSessionSecurityfilterRejectionHandler)

        then:
        noExceptionThrown()

        when:
        ExceptionHandler exceptionHandler = applicationContext.getBean(ExceptionHandler, Qualifiers.byTypeArgumentsClosest(AuthorizationException, Object))

        then:
        noExceptionThrown()
        exceptionHandler instanceof ExtendedSessionSecurityfilterRejectionHandler
    }

    @Requires(property = 'spec.name', value = "RejectionHandlerResolutionSpec")
    @Singleton
    @Replaces(DefaultAuthorizationExceptionHandler)
    static class ExtendedSessionSecurityfilterRejectionHandler implements ExceptionHandler<AuthorizationException, MutableHttpResponse<?>> {

        @Override
        MutableHttpResponse<?> handle(HttpRequest request, AuthorizationException exception) {
            return null
        }
    }

}
