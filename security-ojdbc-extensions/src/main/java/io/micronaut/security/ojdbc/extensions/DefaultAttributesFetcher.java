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
package io.micronaut.security.ojdbc.extensions;

import io.micronaut.core.annotation.Experimental;
import io.micronaut.core.annotation.Internal;
import io.micronaut.security.authentication.Authentication;
import oracle.jdbc.EndUserSecurityContext;
import oracle.jdbc.spi.OracleResourceProvider;
import oracle.sql.json.OracleJsonException;
import oracle.sql.json.OracleJsonFactory;
import oracle.sql.json.OracleJsonObject;
import oracle.sql.json.OracleJsonValue;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.io.StringReader;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static io.micronaut.security.ojdbc.extensions.MicronautEndUserSecurityContextProvider.AUTHORITY_ATTRIBUTE_PREFIX_PARAMETER;
import static io.micronaut.security.ojdbc.extensions.MicronautEndUserSecurityContextProvider.END_USER_CONTEXT_ATTRIBUTE_PARAMETER;

/**
 * Default {@link AttributesFetcher} implementation.
 *
 * @since 5.1.0
 */
@Experimental
@Internal
class DefaultAttributesFetcher implements AttributesFetcher {
    private final OracleJsonFactory oracleJsonFactory;

    /**
     * @param oracleJsonFactory Oracle JSON factory
     * @since 5.1.0
     */
    DefaultAttributesFetcher(OracleJsonFactory oracleJsonFactory) {
        this.oracleJsonFactory = oracleJsonFactory;
    }

    @Override
    public @Nullable Map<String, OracleJsonObject> fetchAttributes(@NonNull Map<OracleResourceProvider.Parameter, CharSequence> parameters,
                                                            @NonNull Authentication authentication) {
        return fetchAttributes(getFixedAttributes(parameters), getAuthorityPrefixAttributes(parameters, authentication));
    }

    /**
     * If multiple maps contain the same key, then attributes in the map at the highest array index
     * overwrite those in maps of lower indices.
     * @param attributesMaps Attributes to add, not null, may not contain null.
     * @return merged attributes
     */
    private @Nullable Map<String, OracleJsonObject> fetchAttributes(Map<String, OracleJsonObject>... attributesMaps) {
        Map<String, OracleJsonObject> merged = null;

        for (Map<String, OracleJsonObject> attributes : attributesMaps) {
            merged = merge(merged, attributes);
        }
        return merged;
    }

    /**
     * Returns END USER CONTEXT attributes configured by the
     * {@link #END_USER_CONTEXT_ATTRIBUTE_PARAMETER}.
     *
     * @param parameters Parameters that configure this provider. Not null, may
     * not contain null.
     *
     * @return Map of END USER CONTEXT attributes to set. Not null, may not
     * contain null.
     */
    private Map<String, OracleJsonObject> getFixedAttributes(Map<OracleResourceProvider.Parameter, CharSequence> parameters) {
        CharSequence fixedAttributes = parameters.get(END_USER_CONTEXT_ATTRIBUTE_PARAMETER);
        if (fixedAttributes == null || fixedAttributes.isEmpty()) {
            return Collections.emptyMap();
        }
        return parseAttributes("attributes configured by the " + END_USER_CONTEXT_ATTRIBUTE_PARAMETER.name() + " parameter",
                fixedAttributes.toString());
    }

    /**
     * Parses a JSON string as a Map of END USER CONTEXT attributes which can be
     * passed to {@link EndUserSecurityContext#withAttributes(Map)}. The structure
     * of the JSON object passed to this method should contain END USER CONTEXT
     * names associated to JSON objects that contain attributes values, as in:
     * <pre>
     *   {
     *     "schema.context_name" : {
     *       "string_attribute" : "value",
     *       "integer_attribute" : 1,
     *     },
     *     "scott.user_info" : {
     *       "first_name" : "George",
     *       "last_name" : "Washington"
     *     }
     *   }
     * </pre>
     *
     * @param name Name to use in error messages if the jsonString cannot be
     * parsed. Not null.
     *
     * @param jsonString String to parse. May be null.
     *
     * @return Map of END USER CONTEXT attributes, not null.
     */
    private Map<String, OracleJsonObject> parseAttributes(String name, String jsonString) {
        if (jsonString == null || jsonString.isEmpty()) {
            return Collections.emptyMap();
        }
        final OracleJsonValue jsonValue;
        try {
            jsonValue = oracleJsonFactory.createJsonTextValue(new StringReader(jsonString));
        } catch (OracleJsonException oracleJsonException) {
            throw new IllegalArgumentException("Failed to parse JSON from " + name, oracleJsonException);
        }
        OracleJsonObject jsonObject = JsonUtils.requireJsonObject(name, jsonValue);
        HashMap<String, OracleJsonObject> attributes = new HashMap<>(jsonObject.size());
        for (Map.Entry<String, OracleJsonValue> entry : jsonObject.entrySet()) {
            String contextName = entry.getKey();
            OracleJsonObject attributeValues = JsonUtils.requireJsonObject(contextName + " within " + name, entry.getValue());
            attributes.put(contextName, attributeValues);
        }
        return attributes;
    }

    /**
     * Merges JSON objects contained with maps.
     * <pre>{@code
     *   Map<String, OracleJsonObject> merged = merge(
     *     Map.of("key", toJSON("{\"a\" : 0, \"b\" : 0}")),
     *     Map.of("key", toJSON("{\"b\" : 1, \"c\" : 1}")));
     *
     *   // This is true:
     *   merged.equals(
     *     Map.of("key", toJSON("{\"a\" : 0, \"b\" : 1, \"c\" : 1}")));
     * }</pre>
     *
     * @param existing Map that contains JSON values which can be overwritten by
     * the current map. May be null, but may not contain null.
     *
     * @param current Map that contains JSON values which can overwrite those in
     * the existing map. May be null, but may not contain null.
     *
     * @return Map that contains all values in the existing map, plus those in
     * the current Map. Not null, may not contain null.
     */
    private static Map<String, OracleJsonObject> merge(
            Map<String, OracleJsonObject> existing,
            Map<String, OracleJsonObject> current) {

        if (existing == null || existing.isEmpty()) {
            return current == null
                    ? Collections.emptyMap()
                    : current;
        }
        if (current == null || current.isEmpty()) {
            return existing;
        }

        HashMap<String, OracleJsonObject> merged = new HashMap<>(existing);

        for (Map.Entry<String, OracleJsonObject> entry : current.entrySet()) {
            merged.merge(
                    entry.getKey(), entry.getValue(), (existingJson, currentJson) -> {
                        existingJson.putAll(currentJson);
                        return existingJson;
                    });
        }

        return merged;
    }

    /**
     * Returns END USER CONTEXT attributes derived from granted authority
     * objects having a String representation that begins with a prefix
     * configured by {@link #AUTHORITY_ATTRIBUTE_PREFIX_PARAMETER}.
     *
     * @param parameters Parameters that configure this provider. Not null, may
     * not contain null.
     *
     * @return Map of END USER CONTEXT attributes to set. Not null, may not
     * contain null.
     */
    private Map<String, OracleJsonObject> getAuthorityPrefixAttributes(
            Map<OracleResourceProvider.Parameter, CharSequence> parameters,
            Authentication authentication) {

        CharSequence authorityPrefix = parameters.get(AUTHORITY_ATTRIBUTE_PREFIX_PARAMETER);
        if (authorityPrefix == null || authorityPrefix.isEmpty()) {
            return Collections.emptyMap();
        }
        Set<String> authorities = RolesUtils.getPrefixedRoles(authorityPrefix.toString(), authentication);
        if (authorities.isEmpty()) {
            return Collections.emptyMap();
        }
        Map<String, OracleJsonObject> attributes = new HashMap<>(authorities.size());
        for (String authority : authorities) {
            Map<String, OracleJsonObject> authorityAttributes = parseAttributes("GrantedAuthority matching prefix configured by the " + AUTHORITY_ATTRIBUTE_PREFIX_PARAMETER.name() + " parameter", authority);
            attributes = merge(attributes, authorityAttributes);
        }
        return attributes;
    }
}
