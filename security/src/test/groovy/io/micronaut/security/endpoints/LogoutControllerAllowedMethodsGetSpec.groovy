package io.micronaut.security.endpoints


import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.MutableHttpResponse
import io.micronaut.security.MockAuthenticationProvider
import io.micronaut.security.SuccessAuthenticationScenario
import io.micronaut.security.handlers.LogoutHandler
import io.micronaut.security.testutils.EmbeddedServerSpecification
import jakarta.inject.Singleton

class LogoutControllerAllowedMethodsGetSpec extends EmbeddedServerSpecification {

    @Override
    String getSpecName() {
        'LogoutControllerAllowedMethodsGetSpec'
    }

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.endpoints.logout.get-allowed': true
        ]
    }

    void "LogoutController can accept GET requests if micronaut.security.endpoints.logout.get-allowed=true"() {
        when:
        client.exchange(HttpRequest.GET("/logout").basicAuth("user", "password"))

        then:
        noExceptionThrown()

        and:
        applicationContext.getBean(CustomLogoutHandler).invocations == 1
    }

    @Requires(property = 'spec.name', value = 'LogoutControllerAllowedMethodsGetSpec')
    @Singleton
    static class CustomLogoutHandler implements LogoutHandler {
        int invocations = 0
        @Override
        MutableHttpResponse<?> logout(HttpRequest<?> request) {
            invocations++
            return HttpResponse.ok()
        }
    }

    @Requires(property = 'spec.name', value = 'LogoutControllerAllowedMethodsGetSpec')
    @Singleton
    static class CustomAuthenticationProvider extends MockAuthenticationProvider {
        CustomAuthenticationProvider() {
            super([new SuccessAuthenticationScenario('user')])
        }
    }
}
