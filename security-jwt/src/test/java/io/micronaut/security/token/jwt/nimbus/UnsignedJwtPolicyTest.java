package io.micronaut.security.token.jwt.nimbus;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.SignedJWT;
import io.micronaut.security.token.jwt.config.JwtConfigurationProperties;
import io.micronaut.security.token.jwt.signature.ReactiveSignatureConfiguration;
import io.micronaut.security.token.jwt.signature.SignatureConfiguration;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class UnsignedJwtPolicyTest {

    private static final List<SignatureConfiguration> IMPERATIVE = List.of(new SignatureConfiguration() {
        @Override
        public String supportedAlgorithmsMessage() {
            return "none";
        }

        @Override
        public boolean supports(JWSAlgorithm algorithm) {
            return false;
        }

        @Override
        public boolean verify(SignedJWT jwt) {
            return false;
        }
    });
    private static final List<ReactiveSignatureConfiguration<SignedJWT>> REACTIVE = List.of(jwt -> Mono.just(false));

    private Logger logger;
    private Level originalLevel;
    private ListAppender<ILoggingEvent> appender;

    @BeforeEach
    void setup() {
        logger = (Logger) LoggerFactory.getLogger(UnsignedJwtPolicy.class);
        originalLevel = logger.getLevel();
        logger.setLevel(Level.WARN);
        appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
    }

    @AfterEach
    void cleanup() {
        logger.detachAppender(appender);
        appender.stop();
        logger.setLevel(originalLevel);
    }

    @ParameterizedTest(name = "accept-unsigned-tokens={0} imperative={1} reactive={2} -> accepted={3}")
    @CsvSource({
            "false, false, false, false",
            "true,  false, false, true",
            "false, true,  false, false",
            "true,  true,  false, false",
            "false, false, true,  false",
            "true,  false, true,  false",
            "true,  true,  true,  false",
    })
    void unsignedJwtIsOnlyAcceptedWhenOptedInWithoutAnySignatureConfiguration(boolean acceptUnsignedTokens,
                                                                               boolean imperative,
                                                                               boolean reactive,
                                                                               boolean accepted) {
        UnsignedJwtPolicy policy = policy(acceptUnsignedTokens, imperative, reactive);

        assertEquals(accepted, policy.acceptsUnsignedJwt());
    }

    @Test
    void warnsAtCreationWhenUnsignedTokensAreAccepted() {
        policy(true, false, false);

        assertEquals(1, warnings().size());
        assertTrue(warnings().get(0).startsWith("micronaut.security.token.jwt.accept-unsigned-tokens is true"));
    }

    @Test
    void doesNotWarnAtCreationWhenFlagIsInertOrDisabled() {
        policy(true, true, false);
        policy(true, false, true);
        policy(false, false, false);

        assertTrue(warnings().isEmpty());
    }

    @Test
    void warnsOnceWhenRejectingForLackOfSignatureConfiguration() {
        UnsignedJwtPolicy policy = policy(false, false, false);

        assertFalse(policy.acceptsUnsignedJwt());
        assertFalse(policy.acceptsUnsignedJwt());

        assertEquals(1, warnings().size());
        assertTrue(warnings().get(0).startsWith("Rejected an unsigned JWT (alg=none) because no signature configuration is present"));
    }

    @Test
    void doesNotWarnWhenRejectingBecauseSignatureConfigurationIsPresent() {
        assertFalse(policy(false, true, false).acceptsUnsignedJwt());

        assertTrue(warnings().isEmpty());
    }

    private static UnsignedJwtPolicy policy(boolean acceptUnsignedTokens, boolean imperative, boolean reactive) {
        JwtConfigurationProperties configuration = new JwtConfigurationProperties();
        configuration.setAcceptUnsignedTokens(acceptUnsignedTokens);
        return new UnsignedJwtPolicy(imperative ? IMPERATIVE : List.of(), reactive ? REACTIVE : List.of(), configuration);
    }

    private List<String> warnings() {
        return appender.list.stream()
                .filter(event -> event.getLevel() == Level.WARN)
                .map(ILoggingEvent::getFormattedMessage)
                .toList();
    }
}
