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
package io.micronaut.security.x509;

import static java.util.regex.Pattern.CASE_INSENSITIVE;

import io.micronaut.context.exceptions.ConfigurationException;
import io.micronaut.core.annotation.Internal;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import org.jspecify.annotations.NonNull;

/**
 * Utility methods for X.509 authentication.
 *
 * @author Sergio del Amo
 * @since 5.4.0
 */
@Internal
public final class X509Utils {

    private X509Utils() {
    }

    /**
     * Compiles the subject DN regex, failing fast if it is invalid or does not contain exactly one capturing group.
     * The group is used to extract the name from the certificate subject DN, so a regex with zero or several
     * groups would never authenticate anybody.
     *
     * @param subjectDnRegex the subject DN regex
     * @return the compiled pattern
     * @throws ConfigurationException if the regex is not a valid regular expression with exactly one capturing group
     */
    @NonNull
    public static Pattern compileSubjectDnRegex(@NonNull String subjectDnRegex) {
        Pattern pattern;
        try {
            pattern = Pattern.compile(subjectDnRegex, CASE_INSENSITIVE);
        } catch (PatternSyntaxException e) {
            throw new ConfigurationException("Invalid value \"" + subjectDnRegex + "\" for " + X509ConfigurationProperties.PREFIX + ".subject-dn-regex: " + e.getMessage(), e);
        }
        int groupCount = pattern.matcher("").groupCount();
        if (groupCount != 1) {
            throw new ConfigurationException("Invalid value \"" + subjectDnRegex + "\" for " + X509ConfigurationProperties.PREFIX + ".subject-dn-regex: the regular expression must contain exactly one capturing group but contains " + groupCount);
        }
        return pattern;
    }
}
