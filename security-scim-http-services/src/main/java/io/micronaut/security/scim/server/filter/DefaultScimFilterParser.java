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
package io.micronaut.security.scim.server.filter;

import io.micronaut.core.annotation.Internal;
import jakarta.inject.Singleton;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

@Internal
@Singleton
final class DefaultScimFilterParser implements ScimFilterParser {
    private static final Pattern ATTRIBUTE_NAME = Pattern.compile("[A-Za-z][A-Za-z0-9_-]*");
    private static final Pattern JSON_NUMBER = Pattern.compile("-?(?:0|[1-9][0-9]*)(?:\\.[0-9]+)?(?:[eE][+-]?[0-9]+)?");

    @Override
    public ScimFilter parse(String expression) {
        if (expression.isBlank()) {
            throw new ScimFilterException("A SCIM filter must not be blank");
        }
        Parser parser = new Parser(tokenize(expression));
        ScimFilter filter = parser.parseExpression();
        parser.expect(TokenType.END, "Unexpected content after filter expression");
        return filter;
    }

    private static List<Token> tokenize(String expression) {
        List<Token> tokens = new ArrayList<>();
        int index = 0;
        while (index < expression.length()) {
            char character = expression.charAt(index);
            if (Character.isWhitespace(character)) {
                index++;
                continue;
            }
            TokenType punctuation = switch (character) {
                case '(' -> TokenType.LEFT_PARENTHESIS;
                case ')' -> TokenType.RIGHT_PARENTHESIS;
                case '[' -> TokenType.LEFT_BRACKET;
                case ']' -> TokenType.RIGHT_BRACKET;
                default -> null;
            };
            if (punctuation != null) {
                tokens.add(new Token(punctuation, Character.toString(character), index));
                index++;
                continue;
            }
            if (character == '"') {
                StringBuilder value = new StringBuilder();
                int start = index++;
                boolean closed = false;
                while (index < expression.length()) {
                    char current = expression.charAt(index++);
                    if (current == '"') {
                        closed = true;
                        break;
                    }
                    if (current != '\\') {
                        value.append(current);
                        continue;
                    }
                    if (index >= expression.length()) {
                        throw syntax("Incomplete string escape", index);
                    }
                    char escaped = expression.charAt(index++);
                    switch (escaped) {
                        case '"', '\\', '/' -> value.append(escaped);
                        case 'b' -> value.append('\b');
                        case 'f' -> value.append('\f');
                        case 'n' -> value.append('\n');
                        case 'r' -> value.append('\r');
                        case 't' -> value.append('\t');
                        case 'u' -> {
                            if (index + 4 > expression.length()) {
                                throw syntax("Incomplete Unicode escape", index);
                            }
                            String hexadecimal = expression.substring(index, index + 4);
                            try {
                                value.append((char) Integer.parseInt(hexadecimal, 16));
                            } catch (NumberFormatException e) {
                                throw syntax("Invalid Unicode escape", index);
                            }
                            index += 4;
                        }
                        default -> throw syntax("Invalid string escape", index - 1);
                    }
                }
                if (!closed) {
                    throw syntax("Unterminated string", start);
                }
                tokens.add(new Token(TokenType.STRING, value.toString(), start));
                continue;
            }
            int start = index;
            while (index < expression.length()) {
                char current = expression.charAt(index);
                if (Character.isWhitespace(current) || current == '(' || current == ')'
                    || current == '[' || current == ']') {
                    break;
                }
                index++;
            }
            if (start == index) {
                throw syntax("Unexpected character", index);
            }
            tokens.add(new Token(TokenType.WORD, expression.substring(start, index), start));
        }
        tokens.add(new Token(TokenType.END, "", expression.length()));
        return tokens;
    }

    private static ScimFilterException syntax(String message, int position) {
        return new ScimFilterException(message + " at position " + position);
    }

    private record Token(TokenType type, String value, int position) {
    }

    private enum TokenType {
        WORD,
        STRING,
        LEFT_PARENTHESIS,
        RIGHT_PARENTHESIS,
        LEFT_BRACKET,
        RIGHT_BRACKET,
        END
    }

    private static final class Parser {
        private final List<Token> tokens;
        private int index;

        private Parser(List<Token> tokens) {
            this.tokens = tokens;
        }

        private ScimFilter parseExpression() {
            return parseOr();
        }

        private ScimFilter parseOr() {
            ScimFilter result = parseAnd();
            while (matchesWord("or")) {
                result = new ScimFilter.Logical(result, ScimFilter.LogicalOperator.OR, parseAnd());
            }
            return result;
        }

        private ScimFilter parseAnd() {
            ScimFilter result = parseUnary();
            while (matchesWord("and")) {
                result = new ScimFilter.Logical(result, ScimFilter.LogicalOperator.AND, parseUnary());
            }
            return result;
        }

        private ScimFilter parseUnary() {
            if (matchesWord("not")) {
                expect(TokenType.LEFT_PARENTHESIS, "Expected '(' after 'not'");
                ScimFilter result = new ScimFilter.Not(parseExpression());
                expect(TokenType.RIGHT_PARENTHESIS, "Expected ')' after negated filter");
                return result;
            }
            if (matches(TokenType.LEFT_PARENTHESIS)) {
                ScimFilter result = parseExpression();
                expect(TokenType.RIGHT_PARENTHESIS, "Expected ')' after grouped filter");
                return result;
            }
            return parseAttributeExpression();
        }

        private ScimFilter parseAttributeExpression() {
            Token attribute = expect(TokenType.WORD, "Expected an attribute path");
            validateAttributePath(attribute);
            if (matches(TokenType.LEFT_BRACKET)) {
                ScimFilter valueFilter = parseExpression();
                expect(TokenType.RIGHT_BRACKET, "Expected ']' after value-path filter");
                return new ScimFilter.ValuePath(attribute.value(), valueFilter);
            }
            Token operator = expect(TokenType.WORD, "Expected a filter operator");
            if (operator.value().equalsIgnoreCase("pr")) {
                return new ScimFilter.Presence(attribute.value());
            }
            ScimFilter.ComparisonOperator comparisonOperator =
                ScimFilter.ComparisonOperator.fromValue(operator.value());
            return new ScimFilter.Comparison(attribute.value(), comparisonOperator, parseValue());
        }

        private ScimFilter.Value parseValue() {
            Token token = current();
            if (matches(TokenType.STRING)) {
                return new ScimFilter.Value(ScimFilter.ValueType.STRING, token.value());
            }
            token = expect(TokenType.WORD, "Expected a comparison value");
            String normalized = token.value().toLowerCase(Locale.ROOT);
            if (normalized.equals("true") || normalized.equals("false")) {
                return new ScimFilter.Value(ScimFilter.ValueType.BOOLEAN, normalized);
            }
            if (normalized.equals("null")) {
                return new ScimFilter.Value(ScimFilter.ValueType.NULL, null);
            }
            if (JSON_NUMBER.matcher(token.value()).matches()) {
                return new ScimFilter.Value(ScimFilter.ValueType.NUMBER, token.value());
            }
            throw syntax("Strings in SCIM filters must be quoted", token.position());
        }

        private void validateAttributePath(Token token) {
            String value = token.value();
            String attributePath = value;
            int schemaSeparator = value.lastIndexOf(':');
            if (schemaSeparator >= 0) {
                String schema = value.substring(0, schemaSeparator);
                attributePath = value.substring(schemaSeparator + 1);
                try {
                    if (!new URI(schema).isAbsolute()) {
                        throw syntax("Invalid attribute schema URI", token.position());
                    }
                } catch (URISyntaxException exception) {
                    throw syntax("Invalid attribute schema URI", token.position());
                }
            }
            if (attributePath.isBlank() || Arrays.stream(attributePath.split("\\.", -1))
                .anyMatch(part -> !ATTRIBUTE_NAME.matcher(part).matches())) {
                throw syntax("Invalid attribute path", token.position());
            }
        }

        private boolean matchesWord(String value) {
            if (current().type() == TokenType.WORD && current().value().equalsIgnoreCase(value)) {
                index++;
                return true;
            }
            return false;
        }

        private boolean matches(TokenType type) {
            if (current().type() == type) {
                index++;
                return true;
            }
            return false;
        }

        private Token expect(TokenType type, String message) {
            Token token = current();
            if (token.type() != type) {
                throw syntax(message, token.position());
            }
            index++;
            return token;
        }

        private Token current() {
            return tokens.get(index);
        }
    }
}
