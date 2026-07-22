package io.micronaut.security.scim.data.jdbc.configuration;

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.data.model.query.builder.sql.Dialect;
import org.jspecify.annotations.Nullable;

@ConfigurationProperties("micronaut.security.scim.data")
class ScimDataConfigurationProperties implements ScimDataConfiguration {
    @Nullable
    private Dialect dialect;

    public @Nullable Dialect getDialect() {
        return dialect;
    }

    public void setDialect(@Nullable Dialect dialect) {
        this.dialect = dialect;
    }
}
