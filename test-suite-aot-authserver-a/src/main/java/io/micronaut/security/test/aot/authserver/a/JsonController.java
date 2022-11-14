package io.micronaut.security.test.aot.authserver.a;

import io.micronaut.context.exceptions.ConfigurationException;
import io.micronaut.core.io.ResourceLoader;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

public abstract class JsonController {

    protected final String json;
    JsonController(ResourceLoader resourceLoader, String fileName) {
        Optional<InputStream> inputStreamOptional = resourceLoader.getResourceAsStream("classpath:" + fileName);
        if (!inputStreamOptional.isPresent()) {
            throw new ConfigurationException("could not retrieve " + fileName);
        }
        InputStream inputStream = inputStreamOptional.get();
        try {
            json = inputStreamToString(inputStream);
        } catch (IOException e) {
            throw new ConfigurationException("could not go from inpustream to json");
        }
    }

    private static String inputStreamToString(InputStream inputStream) throws IOException {

        StringBuilder textBuilder = new StringBuilder();
        try (Reader reader = new BufferedReader(new InputStreamReader
            (inputStream, Charset.forName(StandardCharsets.UTF_8.name())))) {
            int c = 0;
            while ((c = reader.read()) != -1) {
                textBuilder.append((char) c);
            }
        }
        return textBuilder.toString();
    }
}
