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
package io.micronaut.security.scim.data.jdbc.http.service;

import io.micronaut.core.annotation.Internal;
import io.micronaut.http.HttpStatus;
import io.micronaut.security.scim.core.Address;
import io.micronaut.security.scim.core.EnterpriseUser;
import io.micronaut.security.scim.core.Group;
import io.micronaut.security.scim.core.Manager;
import io.micronaut.security.scim.core.Meta;
import io.micronaut.security.scim.core.MultiValuedAttribute;
import io.micronaut.security.scim.core.Name;
import io.micronaut.security.scim.core.ResourceReference;
import io.micronaut.security.scim.core.SchemaUris;
import io.micronaut.security.scim.core.ScimResource;
import io.micronaut.security.scim.core.User;
import io.micronaut.security.scim.server.exception.ScimException;
import io.micronaut.security.scim.server.filter.ScimFilter;
import io.micronaut.security.scim.server.model.ScimPage;
import io.micronaut.security.scim.server.model.ScimQuery;
import io.micronaut.security.scim.server.protocol.ScimErrorType;
import io.micronaut.security.scim.server.protocol.ScimSortOrder;
import org.jspecify.annotations.Nullable;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;

@Internal
final class JdbcScimQueryProcessor {

    private JdbcScimQueryProcessor() {
    }

    static <T extends ScimResource> ScimPage<T> process(List<T> resources, ScimQuery query) {
        List<T> matching = resources.stream()
            .filter(resource -> query.filter() == null || matches(resource, query.filter()))
            .toList();
        if (query.sortBy() != null) {
            Comparator<T> comparator = Comparator.comparing(
                resource -> sortableValue(resource, query.sortBy()),
                Comparator.nullsLast(String.CASE_INSENSITIVE_ORDER)
            );
            if (query.sortOrder() == ScimSortOrder.DESCENDING) {
                comparator = comparator.reversed();
            }
            matching = matching.stream().sorted(comparator).toList();
        }
        int offset = Math.min(query.startIndex() - 1, matching.size());
        int end = Math.min(offset + query.count(), matching.size());
        return new ScimPage<>(matching.subList(offset, end), matching.size(), query.startIndex());
    }

    static boolean matches(Object target, ScimFilter filter) {
        if (filter instanceof ScimFilter.Comparison comparison) {
            List<Object> values = values(target, comparison.attributePath());
            return values.stream().anyMatch(value -> compare(value, comparison.operator(), comparison.value()));
        }
        if (filter instanceof ScimFilter.Presence presence) {
            return values(target, presence.attributePath()).stream().anyMatch(JdbcScimQueryProcessor::isPresent);
        }
        if (filter instanceof ScimFilter.Logical logical) {
            if (logical.operator() == ScimFilter.LogicalOperator.AND) {
                return matches(target, logical.left()) && matches(target, logical.right());
            }
            return matches(target, logical.left()) || matches(target, logical.right());
        }
        if (filter instanceof ScimFilter.Not not) {
            return !matches(target, not.filter());
        }
        if (filter instanceof ScimFilter.ValuePath valuePath) {
            return values(target, valuePath.attributePath()).stream()
                .anyMatch(value -> matches(value, valuePath.filter()));
        }
        throw invalidFilter("Unsupported SCIM filter node " + filter.getClass().getName());
    }

    private static boolean compare(
        @Nullable Object candidate,
        ScimFilter.ComparisonOperator operator,
        ScimFilter.Value expected
    ) {
        if (operator == ScimFilter.ComparisonOperator.EQUAL) {
            return equal(candidate, expected);
        }
        if (operator == ScimFilter.ComparisonOperator.NOT_EQUAL) {
            return !equal(candidate, expected);
        }
        if (candidate == null || expected.value() == null) {
            return false;
        }
        if (expected.type() == ScimFilter.ValueType.NUMBER) {
            try {
                int result = new BigDecimal(String.valueOf(candidate)).compareTo(new BigDecimal(expected.value()));
                return ordered(result, operator);
            } catch (NumberFormatException e) {
                return false;
            }
        }
        String actual = String.valueOf(candidate).toLowerCase(Locale.ROOT);
        String wanted = expected.value().toLowerCase(Locale.ROOT);
        if (operator == ScimFilter.ComparisonOperator.CONTAINS) {
            return actual.contains(wanted);
        }
        if (operator == ScimFilter.ComparisonOperator.STARTS_WITH) {
            return actual.startsWith(wanted);
        }
        if (operator == ScimFilter.ComparisonOperator.ENDS_WITH) {
            return actual.endsWith(wanted);
        }
        return ordered(actual.compareTo(wanted), operator);
    }

    private static boolean equal(@Nullable Object candidate, ScimFilter.Value expected) {
        if (expected.type() == ScimFilter.ValueType.NULL) {
            return candidate == null;
        }
        if (candidate == null || expected.value() == null) {
            return false;
        }
        if (expected.type() == ScimFilter.ValueType.BOOLEAN) {
            return candidate instanceof Boolean value && value == Boolean.parseBoolean(expected.value());
        }
        if (expected.type() == ScimFilter.ValueType.NUMBER) {
            try {
                return new BigDecimal(String.valueOf(candidate)).compareTo(new BigDecimal(expected.value())) == 0;
            } catch (NumberFormatException e) {
                return false;
            }
        }
        return String.valueOf(candidate).equalsIgnoreCase(expected.value());
    }

    private static boolean ordered(int result, ScimFilter.ComparisonOperator operator) {
        return switch (operator) {
            case GREATER_THAN -> result > 0;
            case GREATER_THAN_OR_EQUAL -> result >= 0;
            case LESS_THAN -> result < 0;
            case LESS_THAN_OR_EQUAL -> result <= 0;
            default -> false;
        };
    }

    private static boolean isPresent(@Nullable Object value) {
        return value != null && (!(value instanceof String string) || !string.isEmpty());
    }

    @Nullable
    private static String sortableValue(ScimResource resource, String attributePath) {
        return values(resource, attributePath).stream()
            .filter(JdbcScimQueryProcessor::isPresent)
            .findFirst()
            .map(String::valueOf)
            .orElse(null);
    }

    private static List<Object> values(Object target, String attributePath) {
        Object normalizedTarget = target;
        String normalizedPath = attributePath;
        if (target instanceof User user && attributePath.regionMatches(
            true, 0, SchemaUris.ENTERPRISE_USER + ':', 0, SchemaUris.ENTERPRISE_USER.length() + 1)) {
            normalizedTarget = user.getEnterpriseUser();
            normalizedPath = attributePath.substring(SchemaUris.ENTERPRISE_USER.length() + 1);
        } else if (attributePath.regionMatches(
            true, 0, SchemaUris.USER + ':', 0, SchemaUris.USER.length() + 1)) {
            normalizedPath = attributePath.substring(SchemaUris.USER.length() + 1);
        } else if (attributePath.regionMatches(
            true, 0, SchemaUris.GROUP + ':', 0, SchemaUris.GROUP.length() + 1)) {
            normalizedPath = attributePath.substring(SchemaUris.GROUP.length() + 1);
        } else if (target instanceof ScimResource resource) {
            for (Map.Entry<String, Object> extension : resource.getExtensions().entrySet()) {
                String prefix = extension.getKey() + ':';
                if (attributePath.regionMatches(true, 0, prefix, 0, prefix.length())) {
                    normalizedTarget = extension.getValue();
                    normalizedPath = attributePath.substring(prefix.length());
                    break;
                }
            }
        }
        if (normalizedTarget == null) {
            return List.of();
        }
        String[] segments = normalizedPath.split("\\.");
        List<Object> current = List.of(normalizedTarget);
        for (String segment : segments) {
            List<Object> next = new ArrayList<>();
            for (Object value : current) {
                append(next, property(value, segment));
            }
            current = next;
        }
        return current;
    }

    private static void append(List<Object> values, @Nullable Object value) {
        if (value instanceof Collection<?> collection) {
            collection.stream().filter(item -> item != null).forEach(values::add);
        } else if (value != null) {
            values.add(value);
        }
    }

    @Nullable
    private static Object property(Object target, String name) {
        String property = name.toLowerCase(Locale.ROOT);
        if (target instanceof Map<?, ?> map) {
            return map.entrySet().stream()
                .filter(entry -> String.valueOf(entry.getKey()).equalsIgnoreCase(name))
                .map(Map.Entry::getValue)
                .findFirst()
                .orElse(null);
        }
        if (target instanceof ScimResource resource) {
            Object common = commonProperty(resource, property);
            if (common != null) {
                return common;
            }
        }
        if (target instanceof User user) {
            return userProperty(user, property);
        }
        if (target instanceof Group group) {
            return switch (property) {
                case "displayname" -> group.getDisplayName();
                case "members" -> group.getMembers();
                default -> null;
            };
        }
        if (target instanceof Name value) {
            return switch (property) {
                case "formatted" -> value.formatted();
                case "familyname" -> value.familyName();
                case "givenname" -> value.givenName();
                case "middlename" -> value.middleName();
                case "honorificprefix" -> value.honorificPrefix();
                case "honorificsuffix" -> value.honorificSuffix();
                default -> null;
            };
        }
        if (target instanceof MultiValuedAttribute value) {
            return switch (property) {
                case "value" -> value.value();
                case "type" -> value.type();
                case "primary" -> value.primary();
                case "display" -> value.display();
                case "$ref" -> value.ref();
                default -> null;
            };
        }
        if (target instanceof Address value) {
            return switch (property) {
                case "formatted" -> value.formatted();
                case "streetaddress" -> value.streetAddress();
                case "locality" -> value.locality();
                case "region" -> value.region();
                case "postalcode" -> value.postalCode();
                case "country" -> value.country();
                case "type" -> value.type();
                case "primary" -> value.primary();
                default -> null;
            };
        }
        if (target instanceof ResourceReference value) {
            return switch (property) {
                case "value" -> value.value();
                case "$ref" -> value.ref();
                case "display" -> value.display();
                case "type" -> value.type();
                default -> null;
            };
        }
        if (target instanceof EnterpriseUser value) {
            return switch (property) {
                case "employeenumber" -> value.employeeNumber();
                case "costcenter" -> value.costCenter();
                case "organization" -> value.organization();
                case "division" -> value.division();
                case "department" -> value.department();
                case "manager" -> value.manager();
                default -> null;
            };
        }
        if (target instanceof Manager value) {
            return switch (property) {
                case "value" -> value.value();
                case "$ref" -> value.ref();
                case "displayname" -> value.displayName();
                default -> null;
            };
        }
        if (target instanceof Meta value) {
            return switch (property) {
                case "resourcetype" -> value.resourceType();
                case "created" -> value.created();
                case "lastmodified" -> value.lastModified();
                case "location" -> value.location();
                case "version" -> value.version();
                default -> null;
            };
        }
        return null;
    }

    @Nullable
    private static Object commonProperty(ScimResource resource, String property) {
        return switch (property) {
            case "schemas" -> resource.getSchemas();
            case "id" -> resource.getId();
            case "externalid" -> resource.getExternalId();
            case "meta" -> resource.getMeta();
            default -> null;
        };
    }

    @Nullable
    private static Object userProperty(User user, String property) {
        return switch (property) {
            case "username" -> user.getUserName();
            case "name" -> user.getName();
            case "displayname" -> user.getDisplayName();
            case "nickname" -> user.getNickName();
            case "profileurl" -> user.getProfileUrl();
            case "title" -> user.getTitle();
            case "usertype" -> user.getUserType();
            case "preferredlanguage" -> user.getPreferredLanguage();
            case "locale" -> user.getLocale();
            case "timezone" -> user.getTimezone();
            case "active" -> user.getActive();
            case "emails" -> user.getEmails();
            case "phonenumbers" -> user.getPhoneNumbers();
            case "ims" -> user.getIms();
            case "photos" -> user.getPhotos();
            case "addresses" -> user.getAddresses();
            case "groups" -> user.getGroups();
            case "entitlements" -> user.getEntitlements();
            case "roles" -> user.getRoles();
            case "x509certificates" -> user.getX509Certificates();
            default -> null;
        };
    }

    private static ScimException invalidFilter(String detail) {
        return new ScimException(HttpStatus.BAD_REQUEST, ScimErrorType.INVALID_FILTER, detail);
    }
}
