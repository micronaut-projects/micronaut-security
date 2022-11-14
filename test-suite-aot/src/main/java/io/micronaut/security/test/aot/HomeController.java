package io.micronaut.security.test.aot;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.micronaut.context.exceptions.ConfigurationException;
import io.micronaut.core.io.ResourceLoader;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.security.oauth2.client.DefaultOpenIdProviderMetadata;
import io.micronaut.security.oauth2.client.DefaultOpenIdProviderMetadataFetcher;
import io.micronaut.security.oauth2.client.OpenIdProviderMetadataFetcher;
import jakarta.annotation.security.PermitAll;

import java.io.IOException;
import java.io.InputStream;
import java.util.Optional;


@Controller
class HomeController {

    private final OpenIdProviderMetadataFetcher openIdProviderMetadataFetcher;
    private final DefaultOpenIdProviderMetadata expectedDefaultOpenIdProviderMetadata;

    HomeController(OpenIdProviderMetadataFetcher openIdProviderMetadataFetcher,
                   ObjectMapper objectMapper,
                   ResourceLoader resourceLoader) {
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
    }

    @PermitAll
    @Get
    HttpResponse<?> index() {

        if (DefaultOpenIdProviderMetadataFetcher.OPTIMIZATIONS.findMetadata("foo").isPresent()) {
            return HttpResponse.serverError("Optimizations for foo should not be present");
        }
        if (!DefaultOpenIdProviderMetadataFetcher.OPTIMIZATIONS.findMetadata("autha").isPresent()) {
            return HttpResponse.serverError("Optimizations for autha should be present");
        }
        if (!openIdProviderMetadataFetcher.fetch().equals(expectedDefaultOpenIdProviderMetadata)) {
            return HttpResponse.serverError("fetched OpenID provider metadata at build time does not match expectations");
        }
        return HttpResponse.ok();
    }
}
