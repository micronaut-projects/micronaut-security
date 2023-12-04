package io.micronaut.security.test.aot;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.JWKSet;
import io.micronaut.context.exceptions.ConfigurationException;
import io.micronaut.core.io.ResourceLoader;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.security.oauth2.client.DefaultOpenIdProviderMetadata;
import io.micronaut.security.oauth2.client.DefaultOpenIdProviderMetadataFetcher;
import io.micronaut.security.oauth2.client.OpenIdProviderMetadata;
import io.micronaut.security.oauth2.client.OpenIdProviderMetadataFetcher;
import io.micronaut.security.token.jwt.signature.jwks.DefaultJwkSetFetcher;
import io.micronaut.security.token.jwt.signature.jwks.JwkSetFetcher;
import jakarta.annotation.security.PermitAll;

import java.io.IOException;
import java.io.InputStream;
import java.text.ParseException;
import java.util.Optional;


@Controller
class HomeController {

    private final OpenIdProviderMetadataFetcher openIdProviderMetadataFetcher;
    private final DefaultOpenIdProviderMetadata expectedDefaultOpenIdProviderMetadata;
    private final JWKSet expectedJwkSet;
    private final JwkSetFetcher<JWKSet> jwkSetJwkSetFetcher;

    HomeController(JwkSetFetcher<JWKSet> jwkSetJwkSetFetcher,
                   OpenIdProviderMetadataFetcher openIdProviderMetadataFetcher,
                   ObjectMapper objectMapper,
                   ResourceLoader resourceLoader) {
        this.jwkSetJwkSetFetcher = jwkSetJwkSetFetcher;
        this.openIdProviderMetadataFetcher = openIdProviderMetadataFetcher;
        String fileName = "openidconfiguration.json";
        Optional<InputStream> inputStreamOptional = resourceLoader.getResourceAsStream("classpath:" + fileName);
        if (!inputStreamOptional.isPresent()) {
            throw new ConfigurationException("could not retrieve " + fileName);
        }
        InputStream inputStream = inputStreamOptional.get();

        try {
            this.expectedDefaultOpenIdProviderMetadata = objectMapper.readValue(inputStream, DefaultOpenIdProviderMetadata.class);
        } catch (IOException e) {
            throw new ConfigurationException("could not readValue to  DefaultOpenIdProviderMetadata");
        }

        fileName = "jwks.json";
        inputStreamOptional = resourceLoader.getResourceAsStream("classpath:" + fileName);
        if (!inputStreamOptional.isPresent()) {
            throw new ConfigurationException("could not retrieve " + fileName);
        }
        inputStream = inputStreamOptional.get();
        try {
            this.expectedJwkSet = JWKSet.load(inputStream);
        } catch (IOException | ParseException e) {
            throw new ConfigurationException("could not parse JWKSet from " + fileName);
        }
    }

    @PermitAll
    @Get
    HttpResponse index() {
        if (DefaultOpenIdProviderMetadataFetcher.OPTIMIZATIONS.findMetadata("foo").isPresent()) {
            return HttpResponse.serverError("Optimizations for foo should not be present");
        }
        if (!DefaultOpenIdProviderMetadataFetcher.OPTIMIZATIONS.findMetadata("autha").isPresent()) {
            return HttpResponse.serverError("Optimizations for autha should be present");
        }
        OpenIdProviderMetadata metadata = openIdProviderMetadataFetcher.fetch();
        if (!metadata.getName().equals("autha")) {
            return HttpResponse.serverError("Provider name for OpenID provider metadata fetched at build time should be 'autha' but was "+metadata.getName());
        }
        expectedDefaultOpenIdProviderMetadata.setName("autha");
        if (!metadata.equals(expectedDefaultOpenIdProviderMetadata)) {
            return HttpResponse.serverError("fetched OpenID provider metadata at build time does not match expectations");
        }
        if (DefaultJwkSetFetcher.OPTIMIZATIONS.findJwkSet("foo").isPresent()) {
            return HttpResponse.serverError("JWKSet Optimizations for foo should not be present");
        }
        if (!DefaultJwkSetFetcher.OPTIMIZATIONS.findJwkSet("http://localhost:8081/keys").isPresent()) {
            return HttpResponse.serverError("JWKSet Optimizations for autha should be present");
        }
        if (!jwkSetJwkSetFetcher.fetch(metadata.getName(), "http://localhost:8081/keys").get().toString().equals(expectedJwkSet.toString())) {
            return HttpResponse.serverError("fetched OpenID provider metadata at build time does not match expectations");
        }
        return HttpResponse.ok();
    }
}
