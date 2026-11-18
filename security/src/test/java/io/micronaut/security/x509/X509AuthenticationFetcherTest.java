package io.micronaut.security.x509;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;

class X509AuthenticationFetcherTest {

    /**
     * Certificate whose subject DN is {@code CN=x509test}.
     */
    private static X509Certificate certificate;

    @BeforeAll
    static void loadCertificate() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream inputStream = X509AuthenticationFetcherTest.class.getResourceAsStream("/ssl/x509/client.p12")) {
            keyStore.load(inputStream, "secret".toCharArray());
        }
        certificate = (X509Certificate) keyStore.getCertificate("client");
    }

    @Test
    void nameIsExtractedWithTheCapturingGroup() {
        assertEquals(Optional.of("x509test"), extractName(X509ConfigurationProperties.DEFAULT_SUBJECT_DN_REGEX));
    }

    @Test
    void nameIsEmptyIfTheRegexDoesNotMatch() {
        assertEquals(Optional.empty(), extractName("OU=(.*?)(?:,|$)"));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "CN=(.*?)",
            "CN=(\\s*)"
    })
    void nameIsEmptyIfTheCapturingGroupIsBlank(String regex) {
        assertEquals(Optional.empty(), extractName(regex));
    }

    private static Optional<String> extractName(String regex) {
        return new X509AuthenticationFetcher(configuration(regex)).extractName(certificate);
    }

    private static X509Configuration configuration(String regex) {
        return new X509Configuration() {
            @Override
            public String getSubjectDnRegex() {
                return regex;
            }

            @Override
            public boolean isEnabled() {
                return true;
            }
        };
    }
}
