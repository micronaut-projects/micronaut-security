package tomcat

import io.micronaut.context.annotation.Property
import io.micronaut.context.annotation.Requires
import io.micronaut.core.util.CollectionUtils
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.client.BlockingHttpClient
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.annotation.Client
import io.micronaut.security.testutils.authprovider.MockAuthenticationProvider
import io.micronaut.security.testutils.authprovider.SuccessAuthenticationScenario
import io.micronaut.test.extensions.spock.annotation.MicronautTest
import jakarta.inject.Inject
import jakarta.inject.Singleton
import spock.lang.PendingFeature
import spock.lang.Specification

@Property(name = "micronaut.security.token.jwt.signatures.secret.generator.secret", value = "pleaseChangeThisSecretForANewOne")
@Property(name = "micronaut.security.authentication", value = "bearer")
@Property(name = "spec.name", value = "JwtLoginTest")
@MicronautTest
class JwtLoginSpec extends Specification {

    @Inject
    @Client("/")
    HttpClient httpClient

    @PendingFeature(reason = "fails with java.lang.IllegalStateException: No active propagation context!")
    void "Login is possible in tomcat and body is present"() {
        given:
        BlockingHttpClient client = httpClient.toBlocking()

        when:
        HttpResponse<Map> response = client.exchange(loginRequest(), Map)

        then:
        noExceptionThrown()
        response.getBody().isPresent()
        response.getBody().get().containsKey("access_token")
    }

    private static HttpRequest<?> loginRequest() {
        return HttpRequest.POST("/login",
            CollectionUtils.mapOf("username", "john", "password", "bogus"))
    }

    @Requires(property = "spec.name", value = "JwtLoginTest")
    @Singleton
    static class CustomAuthenticationProvider extends MockAuthenticationProvider {
        CustomAuthenticationProvider() {
            super(Collections.singletonList(new SuccessAuthenticationScenario("john")))
        }
    }
}
