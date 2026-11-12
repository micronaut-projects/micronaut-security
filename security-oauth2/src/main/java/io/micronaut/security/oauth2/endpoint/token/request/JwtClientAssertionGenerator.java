/*
 * Copyright 2017-2026 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.micronaut.security.oauth2.endpoint.token.request;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.micronaut.context.BeanContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.context.exceptions.ConfigurationException;
import io.micronaut.core.util.StringUtils;
import io.micronaut.inject.qualifiers.Qualifiers;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.ClientAssertionConfiguration;
import io.micronaut.security.oauth2.endpoint.AuthenticationMethods;
import io.micronaut.security.oauth2.endpoint.token.request.DefaultTokenEndpointClient.ClientAssertionGenerator;
import io.micronaut.security.oauth2.endpoint.token.request.context.TokenRequestContext;
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse;
import io.micronaut.security.token.jwt.signature.SignatureGeneratorConfiguration;
import io.micronaut.security.token.jwt.signature.secret.SecretSignature;
import io.micronaut.security.token.jwt.signature.secret.SecretSignatureConfiguration;
import jakarta.inject.Singleton;
import org.jspecify.annotations.NonNull;

import java.time.Duration;
import java.util.Collection;
import java.util.Date;
import java.util.UUID;

/**
 * JWT-backed OAuth2 token endpoint client assertion generator.
 */
@Singleton
@Requires(classes = SignatureGeneratorConfiguration.class)
final class JwtClientAssertionGenerator implements ClientAssertionGenerator {

    private final BeanContext beanContext;

    JwtClientAssertionGenerator(BeanContext beanContext) {
        this.beanContext = beanContext;
    }

    @NonNull
    @Override
    public String generate(@NonNull TokenRequestContext<?, ? extends TokenResponse> requestContext,
                           @NonNull ClientAssertionConfiguration clientAssertionConfiguration,
                           @NonNull String authenticationMethod) {
        SignatureGeneratorConfiguration signature = switch (authenticationMethod) {
            case AuthenticationMethods.CLIENT_SECRET_JWT -> clientSecretSignature(requestContext.getClientConfiguration(), clientAssertionConfiguration);
            case AuthenticationMethods.PRIVATE_KEY_JWT -> privateKeySignature(requestContext.getClientConfiguration(), clientAssertionConfiguration);
            default -> throw new ConfigurationException("Unsupported OAuth client assertion authentication method: " + authenticationMethod);
        };
        try {
            SignedJWT signedJWT = signature.sign(clientAssertionClaims(requestContext, clientAssertionConfiguration));
            return signedJWT.serialize();
        } catch (JOSEException e) {
            throw new ConfigurationException("Could not generate OAuth client assertion: " + e.getMessage(), e);
        }
    }

    private SignatureGeneratorConfiguration clientSecretSignature(OauthClientConfiguration clientConfiguration,
                                                                 ClientAssertionConfiguration clientAssertionConfiguration) {
        String clientSecret = clientConfiguration.getClientSecret();
        if (StringUtils.isEmpty(clientSecret)) {
            throw new ConfigurationException("OAuth client " + clientConfiguration.getName() + " requires a client secret for client_secret_jwt authentication");
        }
        JWSAlgorithm algorithm = new JWSAlgorithm(clientAssertionConfiguration.getSigningAlgorithm()
                .orElse(ClientAssertionConfiguration.DEFAULT_SIGNING_ALGORITHM));
        SecretSignatureConfiguration secretSignatureConfiguration = new SecretSignatureConfiguration(clientConfiguration.getName());
        secretSignatureConfiguration.setSecret(clientSecret);
        secretSignatureConfiguration.setJwsAlgorithm(algorithm);
        SecretSignature signature = new SecretSignature(secretSignatureConfiguration);
        if (!signature.supports(algorithm)) {
            throw new ConfigurationException("OAuth client " + clientConfiguration.getName() + " client_secret_jwt does not support signing algorithm " + algorithm.getName());
        }
        return signature;
    }

    private SignatureGeneratorConfiguration privateKeySignature(OauthClientConfiguration clientConfiguration,
                                                               ClientAssertionConfiguration clientAssertionConfiguration) {
        SignatureGeneratorConfiguration signature = clientAssertionConfiguration.getSignerName()
                .map(signerName -> beanContext.findBean(SignatureGeneratorConfiguration.class, Qualifiers.byName(signerName))
                        .orElseThrow(() -> new ConfigurationException("OAuth client " + clientConfiguration.getName() + " private_key_jwt signer not found: " + signerName)))
                .orElseGet(() -> singleSignatureGenerator(clientConfiguration));
        if (signature instanceof SecretSignature) {
            throw new ConfigurationException("OAuth client " + clientConfiguration.getName() + " private_key_jwt requires an asymmetric SignatureGeneratorConfiguration bean");
        }
        return signature;
    }

    private SignatureGeneratorConfiguration singleSignatureGenerator(OauthClientConfiguration clientConfiguration) {
        Collection<SignatureGeneratorConfiguration> signatures = beanContext.getBeansOfType(SignatureGeneratorConfiguration.class);
        if (signatures.isEmpty()) {
            throw new ConfigurationException("OAuth client " + clientConfiguration.getName() + " requires a SignatureGeneratorConfiguration bean for private_key_jwt authentication");
        }
        if (signatures.size() > 1) {
            throw new ConfigurationException("OAuth client " + clientConfiguration.getName() + " private_key_jwt has multiple SignatureGeneratorConfiguration beans; set token.client-assertion.signer-name");
        }
        return signatures.iterator().next();
    }

    private JWTClaimsSet clientAssertionClaims(TokenRequestContext<?, ? extends TokenResponse> requestContext,
                                              ClientAssertionConfiguration clientAssertionConfiguration) {
        Duration lifetime = clientAssertionConfiguration.getLifetime();
        if (lifetime.isZero() || lifetime.isNegative()) {
            throw new ConfigurationException("OAuth client assertion lifetime must be positive");
        }
        OauthClientConfiguration clientConfiguration = requestContext.getClientConfiguration();
        Date issuedAt = new Date();
        Date expiration = Date.from(issuedAt.toInstant().plus(lifetime));
        String clientId = clientConfiguration.getClientId();
        return new JWTClaimsSet.Builder()
                .issuer(clientAssertionConfiguration.getIssuer().orElse(clientId))
                .subject(clientAssertionConfiguration.getSubject().orElse(clientId))
                .audience(clientAssertionConfiguration.getAudience().orElse(requestContext.getEndpoint().getUrl()))
                .issueTime(issuedAt)
                .expirationTime(expiration)
                .jwtID(UUID.randomUUID().toString())
                .build();
    }
}
