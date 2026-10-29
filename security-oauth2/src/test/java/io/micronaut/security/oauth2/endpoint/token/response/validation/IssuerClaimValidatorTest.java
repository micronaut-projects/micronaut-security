package io.micronaut.security.oauth2.endpoint.token.response.validation;

import com.nimbusds.jwt.JWTClaimsSet;
import io.micronaut.context.ApplicationContext;
import io.micronaut.inject.qualifiers.Qualifiers;
import io.micronaut.security.oauth2.client.DefaultOpenIdProviderMetadata;
import io.micronaut.security.oauth2.client.OpenIdProviderMetadata;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.token.response.JWTOpenIdClaims;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdClaims;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The expected issuer of an ID token is the issuer configured for the OpenID client. The {@code issuer} of the
 * provider metadata is controlled by the provider, so it must never widen what the client accepts.
 */
class IssuerClaimValidatorTest {
    private static final String ALPHA_ISSUER = "https://alpha.example.com/oauth2/default";
    private static final String BETA_ISSUER = "https://beta.example.com/oauth2/default";
    private static final String IDCS_TENANT_ISSUER = "https://idcs-214ecfa9143532ca8c3fba0ecb1fe65b.identity.oraclecloud.com";
    private static final String IDCS_ISSUER = "https://identity.oraclecloud.com/";

    private static ApplicationContext context;
    private static IssuerClaimValidator validator;

    @BeforeAll
    static void start() {
        Map<String, Object> configuration = new HashMap<>();
        configuration.put("micronaut.security.oauth2.clients.alpha.client-id", "alpha-client");
        configuration.put("micronaut.security.oauth2.clients.alpha.client-secret", "test-fixture-not-a-secret");
        configuration.put("micronaut.security.oauth2.clients.alpha.openid.issuer", ALPHA_ISSUER);
        configuration.put("micronaut.security.oauth2.clients.idcs.client-id", "idcs-client");
        configuration.put("micronaut.security.oauth2.clients.idcs.client-secret", "test-fixture-not-a-secret");
        configuration.put("micronaut.security.oauth2.clients.idcs.openid.issuer", IDCS_TENANT_ISSUER);
        configuration.put("micronaut.security.oauth2.clients.idcs.openid.issuer-identifier", IDCS_ISSUER);
        configuration.put("micronaut.security.oauth2.clients.idcs-tenant.client-id", "idcs-client");
        configuration.put("micronaut.security.oauth2.clients.idcs-tenant.client-secret", "test-fixture-not-a-secret");
        configuration.put("micronaut.security.oauth2.clients.idcs-tenant.openid.issuer", IDCS_TENANT_ISSUER);
        configuration.put("micronaut.security.oauth2.clients.manual.client-id", "manual-client");
        configuration.put("micronaut.security.oauth2.clients.manual.client-secret", "test-fixture-not-a-secret");
        configuration.put("micronaut.security.oauth2.clients.manual.openid.authorization.url", ALPHA_ISSUER + "/v1/authorize");
        configuration.put("micronaut.security.oauth2.clients.manual.openid.token.url", ALPHA_ISSUER + "/v1/token");
        context = ApplicationContext.run(configuration);
        validator = context.getBean(IssuerClaimValidator.class);
    }

    @AfterAll
    static void stop() {
        context.close();
    }

    @Test
    void issuerClaimMatchingTheConfiguredAndDiscoveredIssuerIsAccepted() {
        assertTrue(validator.validate(claims(ALPHA_ISSUER), client("alpha"), metadata("alpha", ALPHA_ISSUER)));
    }

    @Test
    void issuerClaimOfAnotherProviderIsRejectedEvenIfTheDiscoveryDocumentAnnouncesIt() {
        // provider alpha announces beta's issuer in its discovery document
        OpenIdProviderMetadata spoofed = metadata("alpha", BETA_ISSUER);
        assertFalse(validator.validate(claims(BETA_ISSUER), client("alpha"), spoofed));
        assertFalse(validator.validate(claims(ALPHA_ISSUER), client("alpha"), spoofed));
    }

    @Test
    void issuerClaimNotMatchingTheConfiguredIssuerIsRejected() {
        assertFalse(validator.validate(claims(BETA_ISSUER), client("alpha"), metadata("alpha", ALPHA_ISSUER)));
        assertFalse(validator.validate(claims(ALPHA_ISSUER + "/other"), client("alpha"), metadata("alpha", ALPHA_ISSUER)));
        assertFalse(validator.validate(claims("https://example.com"), client("alpha"), metadata("alpha", ALPHA_ISSUER)));
    }

    @Test
    void missingIssuerClaimIsRejected() {
        assertFalse(validator.validate(new JWTOpenIdClaims(new JWTClaimsSet.Builder().build()), client("alpha"), metadata("alpha", ALPHA_ISSUER)));
    }

    @Test
    void issuerClaimMustStillMatchTheProviderIssuerIdentifierExactly() {
        assertFalse(validator.validate(claims(ALPHA_ISSUER + "/"), client("alpha"), metadata("alpha", ALPHA_ISSUER)));
        assertFalse(validator.validate(claims(ALPHA_ISSUER.replace("https://", "http://")), client("alpha"), metadata("alpha", ALPHA_ISSUER)));
    }

    @Test
    void issuerIdentifierSeparatesTheExpectedIssuerFromTheDiscoveryUrl() {
        // Oracle IDCS: tenant specific discovery URL, provider wide issuer in tokens
        assertTrue(validator.validate(claims(IDCS_ISSUER), client("idcs"), metadata("idcs", IDCS_ISSUER)));
        assertFalse(validator.validate(claims(IDCS_TENANT_ISSUER), client("idcs"), metadata("idcs", IDCS_ISSUER)));
        assertFalse(validator.validate(claims(BETA_ISSUER), client("idcs"), metadata("idcs", IDCS_ISSUER)));
    }

    @Test
    void parentDomainIssuerIsRejectedWithoutIssuerIdentifier() {
        assertFalse(validator.validate(claims(IDCS_ISSUER), client("idcs-tenant"), metadata("idcs-tenant", IDCS_ISSUER)));
        assertFalse(validator.validate(claims("https://identity.oraclecloud.com"), client("idcs-tenant"), metadata("idcs-tenant", "https://identity.oraclecloud.com")));
        assertTrue(validator.validate(claims(IDCS_TENANT_ISSUER), client("idcs-tenant"), metadata("idcs-tenant", IDCS_TENANT_ISSUER)));
    }

    @Test
    void withoutConfiguredIssuerTheProviderMetadataIssuerIsTheExpectedIssuer() {
        assertTrue(validator.validate(claims(ALPHA_ISSUER), client("manual"), metadata("manual", ALPHA_ISSUER)));
        assertFalse(validator.validate(claims(BETA_ISSUER), client("manual"), metadata("manual", ALPHA_ISSUER)));
        assertFalse(validator.validate(claims(ALPHA_ISSUER), client("manual"), new DefaultOpenIdProviderMetadata()));
    }

    private static OauthClientConfiguration client(String name) {
        return context.getBean(OauthClientConfiguration.class, Qualifiers.byName(name));
    }

    private static OpenIdProviderMetadata metadata(String name, String issuer) {
        DefaultOpenIdProviderMetadata metadata = new DefaultOpenIdProviderMetadata();
        metadata.setIssuer(issuer);
        return metadata;
    }

    private static OpenIdClaims claims(String issuer) {
        return new JWTOpenIdClaims(new JWTClaimsSet.Builder().issuer(issuer).build());
    }
}
