package io.micronaut.security.oauth2;

import io.micronaut.context.annotation.Property;
import io.micronaut.core.util.StringUtils;
import io.micronaut.security.oauth2.client.IdTokenClaimsValidator;
import io.micronaut.security.token.Claims;
import io.micronaut.security.token.MapClaims;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.RepetitionInfo;

import java.util.List;
import java.util.Map;
import java.util.concurrent.*;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

@MicronautTest(startApplication = false)
@Property(name = "micronaut.security.enabled", value = StringUtils.TRUE)
@Property(name = "micronaut.security.authentication", value = "idtoken")
@Property(name = "micronaut.security.oauth2.clients.test.client-id", value = ClaimsUtilsConcurrentModificationTest.CLIENT_ID)
@Property(name = "micronaut.security.oauth2.clients.test.openid.issuer", value = ClaimsUtilsConcurrentModificationTest.ISSUER)
class ClaimsUtilsConcurrentModificationTest {

    static final String CLIENT_ID = "test-clientId";
    static final String ISSUER = "https://example.com";

    @Inject
    IdTokenClaimsValidator<Object> cut;

    private final ExecutorService executor = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());

    @RepeatedTest(500)
    void validateIssuerWithConcurrentAccess(RepetitionInfo repetitionInfo) throws Exception {
        String currentIssuer = "issuer-" + repetitionInfo.getCurrentRepetition();
        MapClaims claims = new MapClaims(Map.of(
            Claims.ISSUER, currentIssuer,
            Claims.AUDIENCE, List.of(CLIENT_ID)
        ));

        Callable<Object> task = () -> cut.validate(claims, null);

        List<Future<Object>> futures = executor.invokeAll(List.of(task, task));
        for (Future<Object> future : futures) {
            assertDoesNotThrow(() -> future.get());
        }
    }
}
