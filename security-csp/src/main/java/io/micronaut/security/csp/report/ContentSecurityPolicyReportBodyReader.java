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
package io.micronaut.security.csp.report;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.type.Argument;
import io.micronaut.core.type.Headers;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Consumes;
import io.micronaut.http.body.MessageBodyReader;
import io.micronaut.http.codec.CodecException;
import io.micronaut.json.JsonMapper;
import io.micronaut.json.tree.JsonNode;
import io.micronaut.serde.annotation.Serdeable;
import jakarta.inject.Singleton;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * Decodes the Reporting API's dedicated JSON media type.
 */
@Internal
@Singleton
@Consumes(ContentSecurityPolicyController.APPLICATION_REPORTS_JSON)
final class ContentSecurityPolicyReportBodyReader implements MessageBodyReader<List<ContentSecurityPolicyReport>> {
    private final JsonMapper jsonMapper;

    ContentSecurityPolicyReportBodyReader(JsonMapper jsonMapper) {
        this.jsonMapper = jsonMapper;
    }

    @Override
    public @Nullable List<ContentSecurityPolicyReport> read(Argument<List<ContentSecurityPolicyReport>> type,
                                                            @Nullable MediaType mediaType,
                                                            Headers httpHeaders,
                                                            InputStream inputStream) throws CodecException {
        try {
            List<SerializedContentSecurityPolicyReport> serializedReports = jsonMapper.readValue(
                inputStream,
                Argument.listOf(SerializedContentSecurityPolicyReport.class)
            );
            if (serializedReports == null) {
                return null;
            }
            List<ContentSecurityPolicyReport> reports = new ArrayList<>(serializedReports.size());
            for (SerializedContentSecurityPolicyReport report : serializedReports) {
                reports.add(toReport(report));
            }
            return reports;
        } catch (IOException e) {
            throw new CodecException("Error decoding Reporting API request body: " + e.getMessage(), e);
        }
    }

    private ContentSecurityPolicyReport toReport(SerializedContentSecurityPolicyReport report) throws IOException {
        String reportType = report.type();
        JsonNode serializedBody = report.body();
        if (reportType == null || serializedBody == null || serializedBody.isNull()) {
            throw new CodecException("A Content Security Policy report type and body are required");
        }
        ContentSecurityPolicyReportBody body = switch (reportType) {
            case ContentSecurityPolicyReport.TYPE_CSP_VIOLATION -> jsonMapper.readValueFromTree(
                serializedBody,
                ContentSecurityPolicyViolationReportBody.class
            );
            case ContentSecurityPolicyReport.TYPE_CSP_HASH -> jsonMapper.readValueFromTree(
                serializedBody,
                ContentSecurityPolicyHashReportBody.class
            );
            default -> throw new CodecException("Unsupported Content Security Policy report type: " + reportType);
        };
        if (body == null) {
            throw new CodecException("A Content Security Policy report body is required");
        }
        return new ContentSecurityPolicyReport(
            report.age(),
            reportType,
            report.url(),
            report.userAgent(),
            body
        );
    }
}

@Serdeable
record SerializedContentSecurityPolicyReport(
    Long age,
    String type,
    String url,
    @JsonProperty("user_agent") String userAgent,
    @Nullable JsonNode body
) {
}
