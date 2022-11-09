/*
 * Copyright 2017-2020 original authors
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
package io.micronaut.security.config;

import io.micronaut.context.exceptions.ConfigurationException;
import io.micronaut.core.convert.ConversionContext;
import io.micronaut.core.convert.ConversionService;
import io.micronaut.core.convert.TypeConverter;
import io.micronaut.core.naming.conventions.StringConvention;
import io.micronaut.http.HttpMethod;
import io.micronaut.http.context.ServerContextPathProvider;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * @author Sergio del Amo
 * @since 1.0
 */
@Singleton
public class InterceptUrlMapConverter implements TypeConverter<Map<String, Object>, InterceptUrlMapPattern> {

    private static final String PATTERN = "pattern";
    private static final String ACCESS = "access";
    private static final String HTTP_METHOD = "http-method";

    private final ConversionService conversionService;

    /**
     * @param conversionService     The conversion service
     */
    @Inject
    InterceptUrlMapConverter(ConversionService conversionService) {
        this.conversionService = conversionService;
    }

    /**
     * @param conversionService     The conversion service
     * @param serverContextPathProviders context path providers
     * @param interceptUrlMapPrependPatternWithContextPath Whether the intercept URL patterns should be prepended with context path if defined.
     * @deprecated Use {@link InterceptUrlMapConverter(ConversionService)}  instead.
     */
    @Deprecated
    InterceptUrlMapConverter(ConversionService conversionService,
                             List<ServerContextPathProvider> serverContextPathProviders, // Inject list because when using Tomcat there is a multiple beans exception
                             boolean interceptUrlMapPrependPatternWithContextPath) {
        this(conversionService);
    }

    /**
     * @param conversionService     The conversion service
     * @param serverContextPathProvider context path provider
     * @param interceptUrlMapPrependPatternWithContextPath Whether the intercept URL patterns should be prepended with context path if defined.
     * @deprecated Use {@link InterceptUrlMapConverter(ConversionService)}  instead.
     */
    @Deprecated
    InterceptUrlMapConverter(ConversionService conversionService,
                             ServerContextPathProvider serverContextPathProvider,
                             boolean interceptUrlMapPrependPatternWithContextPath) {
        this(conversionService);
    }

    /**
     * @param m          a Map in the configuration
     * @param targetType The target type being converted to
     * @param context    The {@link ConversionContext}
     * @return An optional InterceptUrlMapConverter
     */
    @Override
    public Optional<InterceptUrlMapPattern> convert(Map<String, Object> m, Class<InterceptUrlMapPattern> targetType, ConversionContext context) {
        if (m == null) {
            return Optional.empty();
        }
        m = transform(m);
        Optional<String> optionalPattern = conversionService.convert(m.get(PATTERN), String.class);
        if (optionalPattern.isPresent()) {
            Optional<List<String>> optionalAccessList = conversionService.convert(m.get(ACCESS), List.class);
            optionalAccessList = optionalAccessList.map(list -> list.stream()
                .map(o -> conversionService.convert(o, String.class))
                .filter(Optional::isPresent)
                .map(Optional::get)
                .map(String.class::cast)
                .collect(Collectors.toList()));
            if (optionalAccessList.isPresent()) {
                Optional<HttpMethod> httpMethod;
                if (m.containsKey(HTTP_METHOD)) {
                    httpMethod = conversionService.convert(m.get(HTTP_METHOD), HttpMethod.class);
                    if (!httpMethod.isPresent()) {
                        throw new ConfigurationException(String.format("interceptUrlMap configuration record %s rejected due to invalid %s key.", m.toString(), HTTP_METHOD));
                    }
                } else {
                    httpMethod = Optional.empty();
                }
                List<String> accessList = optionalAccessList.get();
                return optionalPattern
                    .map(pattern -> new InterceptUrlMapPattern(pattern, accessList, httpMethod.orElse(null)));
            } else {
                throw new ConfigurationException(String.format("interceptUrlMap configuration record %s rejected due to missing or empty %s key.", m.toString(), ACCESS));
            }
        } else {
            throw new ConfigurationException(String.format("interceptUrlMap configuration record %s rejected due to missing %s key.", m.toString(), PATTERN));
        }
    }

    private Map<String, Object> transform(Map<String, Object> map) {
        Map<String, Object> transformed = new HashMap<>();
        StringConvention convention = StringConvention.HYPHENATED;
        for (Map.Entry<String, Object> entry: map.entrySet()) {
            transformed.put(convention.format(entry.getKey()), entry.getValue());
        }
        return transformed;
    }
}
