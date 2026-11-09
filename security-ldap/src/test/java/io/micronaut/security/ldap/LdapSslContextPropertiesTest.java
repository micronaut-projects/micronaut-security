package io.micronaut.security.ldap;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldif.LDIFReader;
import com.unboundid.util.ssl.KeyStoreKeyManager;
import com.unboundid.util.ssl.SSLUtil;
import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.unboundid.util.ssl.cert.ManageCertificates;
import io.micronaut.context.ApplicationContext;
import io.micronaut.security.authentication.AuthenticationFailed;
import io.micronaut.security.authentication.AuthenticationFailureReason;
import io.micronaut.security.authentication.AuthenticationRequest;
import io.micronaut.security.authentication.AuthenticationException;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.ldap.configuration.LdapConfiguration;
import io.micronaut.security.ldap.context.ContextBuilder;
import io.micronaut.security.ldap.context.ContextSettings;
import io.micronaut.security.ldap.context.DefaultContextBuilder;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import reactor.core.publisher.Mono;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Turning on TLS through {@code context.properties} ({@code java.naming.security.protocol=ssl} with an
 * {@code ldap://} URL) must actually reach JNDI. The directory below only accepts TLS, so a bind that
 * ignored the property would be sent in cleartext and fail.
 */
class LdapSslContextPropertiesTest {

    private static final String MANAGER_DN = "cn=admin,dc=example,dc=com";
    private static final String MANAGER_PASSWORD = "password";
    private static final String KEY_STORE_ALIAS = "ldaps-test-fixture";
    private static final String KEY_STORE_PASSWORD = "test-fixture-not-a-secret";

    private static InMemoryDirectoryServer server;

    @BeforeAll
    static void startLdapsServer() throws Exception {
        InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig("dc=example,dc=com");
        config.addAdditionalBindCredentials(MANAGER_DN, MANAGER_PASSWORD);
        File keyStore = generateLocalhostCertificate();
        SSLUtil serverSslUtil = new SSLUtil(new KeyStoreKeyManager(keyStore, KEY_STORE_PASSWORD.toCharArray(), "PKCS12", KEY_STORE_ALIAS), null);
        config.setListenerConfigs(InMemoryListenerConfig.createLDAPSConfig("LDAPS", 0, serverSslUtil.createSSLServerSocketFactory()));
        server = new InMemoryDirectoryServer(config);
        try (InputStream ldif = Objects.requireNonNull(LdapSslContextPropertiesTest.class.getClassLoader().getResourceAsStream("basic.ldif"), "basic.ldif is missing from the test classpath")) {
            server.importFromLDIF(true, new LDIFReader(ldif));
        }
        server.startListening();
    }

    @AfterAll
    static void stopLdapsServer() {
        if (server != null) {
            server.shutDown(true);
        }
    }

    @Test
    void sslContextPropertyWithLdapUrlAuthenticatesOverTls() {
        try (ApplicationContext ctx = ApplicationContext.run(tlsViaContextProperties(), "test")) {
            LdapAuthenticationProvider<Object> provider = ctx.getBean(LdapAuthenticationProvider.class);

            AuthenticationResponse response = Mono.from(provider.authenticate(null, request("riemann", "password")))
                .onErrorResume(AuthenticationException.class, failure -> Mono.just(failure.getResponse()))
                .block();
            assertTrue(response.isAuthenticated());
            assertEquals("riemann", response.getAuthentication().orElseThrow().getName());
            assertTrue(response.getAuthentication().orElseThrow().getRoles().contains("Mathematicians"));

            AuthenticationResponse rejected = Mono.from(provider.authenticate(null, request("riemann", "wrong-password")))
                .onErrorResume(AuthenticationException.class, failure -> Mono.just(failure.getResponse()))
                .block();
            assertFalse(rejected.isAuthenticated());
            assertEquals(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH, assertInstanceOf(AuthenticationFailed.class, rejected).getReason());
        }
    }

    @Test
    void withoutTlsContextPropertiesCleartextBindDoesNotReachTheTlsOnlyDirectory() {
        Map<String, Object> properties = new HashMap<>(tlsViaContextProperties());
        properties.keySet().removeIf(key -> key.startsWith("micronaut.security.ldap.default.context.properties."));
        try (ApplicationContext ctx = ApplicationContext.run(properties, "test")) {
            LdapAuthenticationProvider<Object> provider = ctx.getBean(LdapAuthenticationProvider.class);

            AuthenticationResponse response = Mono.from(provider.authenticate(null, request("riemann", "password")))
                .onErrorResume(AuthenticationException.class, failure -> Mono.just(failure.getResponse()))
                .block();
            assertFalse(response.isAuthenticated());
            assertEquals(AuthenticationFailureReason.UNKNOWN, assertInstanceOf(AuthenticationFailed.class, response).getReason());
        }
    }

    @Test
    void scalarContextPropertyValuesAreConvertedToStringsForJndi() throws NamingException {
        Map<String, Object> properties = new HashMap<>(tlsViaContextProperties());
        // YAML binds unquoted numbers and booleans as Integer and Boolean; the JDK LDAP provider casts every entry to String
        properties.put("micronaut.security.ldap.default.context.properties.com.sun.jndi.ldap.connect.timeout", 5000);
        properties.put("micronaut.security.ldap.default.context.properties.com.sun.jndi.ldap.read.timeout", 5000);
        properties.put("micronaut.security.ldap.default.context.properties.java.naming.ldap.typesOnly", false);
        try (ApplicationContext ctx = ApplicationContext.run(properties, "test")) {
            ContextBuilder contextBuilder = ctx.getBean(ContextBuilder.class);
            DirContext context = contextBuilder.build(ctx.getBean(LdapConfiguration.class).getManagerSettings());
            try {
                assertEquals("5000", context.getEnvironment().get("com.sun.jndi.ldap.connect.timeout"));
                assertEquals("5000", context.getEnvironment().get("com.sun.jndi.ldap.read.timeout"));
                assertEquals("false", context.getEnvironment().get("java.naming.ldap.typesOnly"));
            } finally {
                contextBuilder.close(context);
            }

            LdapAuthenticationProvider<Object> provider = ctx.getBean(LdapAuthenticationProvider.class);
            assertTrue(Mono.from(provider.authenticate(null, request("riemann", "password")))
                .onErrorResume(AuthenticationException.class, failure -> Mono.just(failure.getResponse()))
                .block().isAuthenticated());
        }
    }

    @Test
    void reservedJndiKeysInContextPropertiesCannotMakeWrongPasswordSucceed() {
        Map<String, Object> properties = new HashMap<>(tlsViaContextProperties());
        properties.put("micronaut.security.ldap.default.context.properties.java.naming.security.authentication", "none");
        properties.put("micronaut.security.ldap.default.context.properties.java.naming.security.principal", MANAGER_DN);
        properties.put("micronaut.security.ldap.default.context.properties.java.naming.security.credentials", "ignored");
        properties.put("micronaut.security.ldap.default.context.properties.com.sun.jndi.ldap.connect.pool", "true");
        try (ApplicationContext ctx = ApplicationContext.run(properties, "test")) {
            LdapAuthenticationProvider<Object> provider = ctx.getBean(LdapAuthenticationProvider.class);

            AuthenticationResponse rejected = Mono.from(provider.authenticate(null, request("riemann", "wrong-password")))
                .onErrorResume(AuthenticationException.class, failure -> Mono.just(failure.getResponse()))
                .block();
            assertFalse(rejected.isAuthenticated());
            assertEquals(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH, assertInstanceOf(AuthenticationFailed.class, rejected).getReason());

            assertTrue(Mono.from(provider.authenticate(null, request("riemann", "password")))
                .onErrorResume(AuthenticationException.class, failure -> Mono.just(failure.getResponse()))
                .block().isAuthenticated());
        }
    }

    @Test
    void reservedKeysAreReportedOncePerKeyAtWarnLevel() {
        Map<String, Object> properties = new HashMap<>(tlsViaContextProperties());
        properties.put("micronaut.security.ldap.default.context.properties.java.naming.security.authentication", "none");
        properties.put("micronaut.security.ldap.default.context.properties.java.naming.security.credentials", "ignored");
        Logger logger = (Logger) LoggerFactory.getLogger(DefaultContextBuilder.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        try (ApplicationContext ctx = ApplicationContext.run(properties, "test")) {
            LdapAuthenticationProvider<Object> provider = ctx.getBean(LdapAuthenticationProvider.class);
            // each login builds a manager context and a user context
            assertTrue(Mono.from(provider.authenticate(null, request("riemann", "password")))
                .onErrorResume(AuthenticationException.class, failure -> Mono.just(failure.getResponse()))
                .block().isAuthenticated());
            assertTrue(Mono.from(provider.authenticate(null, request("riemann", "password")))
                .onErrorResume(AuthenticationException.class, failure -> Mono.just(failure.getResponse()))
                .block().isAuthenticated());

            assertEquals(1, reservedKeyWarnings(appender, "java.naming.security.authentication"));
            assertEquals(1, reservedKeyWarnings(appender, "java.naming.security.credentials"));
        } finally {
            logger.detachAppender(appender);
            appender.stop();
        }
    }

    @Test
    void stringValueForObjectValuedJndiKeyFailsTheBindInsteadOfThrowing() {
        Map<String, Object> properties = new HashMap<>(tlsViaContextProperties());
        // com.sun.jndi.ldap.trace.ber takes an OutputStream; the JDK casts the value without checking it
        properties.put("micronaut.security.ldap.default.context.properties.com.sun.jndi.ldap.trace.ber", "true");
        try (ApplicationContext ctx = ApplicationContext.run(properties, "test")) {
            ContextBuilder contextBuilder = ctx.getBean(ContextBuilder.class);
            NamingException e = assertThrows(NamingException.class, () -> contextBuilder.build(ctx.getBean(LdapConfiguration.class).getManagerSettings()));
            assertInstanceOf(ClassCastException.class, e.getRootCause());

            LdapAuthenticationProvider<Object> provider = ctx.getBean(LdapAuthenticationProvider.class);
            AuthenticationResponse response = Mono.from(provider.authenticate(null, request("riemann", "password")))
                .onErrorResume(AuthenticationException.class, failure -> Mono.just(failure.getResponse()))
                .block();
            assertFalse(response.isAuthenticated());
            assertEquals(AuthenticationFailureReason.UNKNOWN, assertInstanceOf(AuthenticationFailed.class, response).getReason());
        }
    }

    private static long reservedKeyWarnings(ListAppender<ILoggingEvent> appender, String key) {
        return appender.list.stream()
                .filter(event -> event.getLevel() == Level.WARN)
                .filter(event -> event.getFormattedMessage().contains("Ignoring LDAP context property '" + key + "'"))
                .count();
    }

    @Test
    void reservedKeysAreIgnoredByTheContextBuilder() throws NamingException {
        try (ApplicationContext ctx = ApplicationContext.run(tlsViaContextProperties(), "test")) {
            ContextBuilder contextBuilder = ctx.getBean(ContextBuilder.class);
            ContextSettings base = ctx.getBean(LdapConfiguration.class).getManagerSettings();
            Map<String, Object> extra = new HashMap<>(base.getAdditionalProperties());
            extra.put("java.naming.security.authentication", "none");
            extra.put("java.naming.security.credentials", "wrong");
            extra.put("com.sun.jndi.ldap.connect.pool", Boolean.toString(!base.getPooled()));
            DirContext context = contextBuilder.build(new AdditionalPropertiesContextSettings(base, extra));
            try {
                assertEquals("simple", context.getEnvironment().get("java.naming.security.authentication"));
                assertEquals(MANAGER_PASSWORD, context.getEnvironment().get("java.naming.security.credentials"));
                assertEquals(base.getPooled(), "true".equals(context.getEnvironment().get("com.sun.jndi.ldap.connect.pool")));
            } finally {
                contextBuilder.close(context);
            }
        }
    }

    /**
     * Generates a throwaway self-signed server certificate for {@code localhost}, so that JNDI's LDAPS endpoint
     * identification passes while the client only needs to trust the certificate itself.
     */
    private static File generateLocalhostCertificate() throws Exception {
        File keyStore = Files.createTempFile("ldaps-test-fixture", ".p12").toFile();
        keyStore.deleteOnExit();
        Files.delete(keyStore.toPath());
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        ResultCode resultCode = ManageCertificates.main(null, output, output,
                "generate-self-signed-certificate",
                "--keystore", keyStore.getAbsolutePath(),
                "--keystore-password", KEY_STORE_PASSWORD,
                "--keystore-type", "PKCS12",
                "--alias", KEY_STORE_ALIAS,
                "--subject-dn", "CN=localhost,OU=ldaps-test-fixture",
                "--days-valid", "2",
                "--key-algorithm", "RSA",
                "--key-size-bits", "2048",
                "--signature-algorithm", "SHA256withRSA",
                "--subject-alternative-name-dns", "localhost",
                "--subject-alternative-name-ip-address", "127.0.0.1",
                "--subject-alternative-name-ip-address", "::1",
                "--key-usage", "digitalSignature",
                "--key-usage", "keyEncipherment",
                "--extended-key-usage", "server-auth");
        if (resultCode != ResultCode.SUCCESS) {
            throw new IllegalStateException("Could not generate the test certificate: " + output.toString(StandardCharsets.UTF_8));
        }
        return keyStore;
    }

    private static Map<String, Object> tlsViaContextProperties() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("micronaut.security.ldap.default.enabled", true);
        properties.put("micronaut.security.ldap.default.context.server", "ldap://localhost:" + server.getListenPort());
        properties.put("micronaut.security.ldap.default.context.managerDn", MANAGER_DN);
        properties.put("micronaut.security.ldap.default.context.managerPassword", MANAGER_PASSWORD);
        properties.put("micronaut.security.ldap.default.context.properties.java.naming.security.protocol", "ssl");
        properties.put("micronaut.security.ldap.default.context.properties.java.naming.ldap.factory.socket", TrustAllSslSocketFactory.class.getName());
        properties.put("micronaut.security.ldap.default.search.base", "dc=example,dc=com");
        properties.put("micronaut.security.ldap.default.groups.enabled", true);
        properties.put("micronaut.security.ldap.default.groups.base", "dc=example,dc=com");
        return properties;
    }

    private static AuthenticationRequest<Object, Object> request(String username, String password) {
        return new AuthenticationRequest<>() {
            @Override
            public Object getIdentity() {
                return username;
            }

            @Override
            public Object getSecret() {
                return password;
            }
        };
    }

    /**
     * A custom {@link ContextSettings} which replaces the additional properties of the delegate.
     */
    private record AdditionalPropertiesContextSettings(ContextSettings delegate, Map<String, Object> additionalProperties) implements ContextSettings {

        @Override
        public boolean getPooled() {
            return delegate.getPooled();
        }

        @Override
        public String getFactory() {
            return delegate.getFactory();
        }

        @Override
        public String getUrl() {
            return delegate.getUrl();
        }

        @Override
        public String getDn() {
            return delegate.getDn();
        }

        @Override
        public String getPassword() {
            return delegate.getPassword();
        }

        @Override
        public Map<String, Object> getAdditionalProperties() {
            return additionalProperties;
        }
    }
}
