package io.micronaut.security.scim.data.jdbc.repositories.h2;

import io.micronaut.context.annotation.Requires;
import io.micronaut.data.jdbc.annotation.JdbcRepository;
import io.micronaut.data.model.query.builder.sql.Dialect;
import io.micronaut.security.scim.data.jdbc.repositories.ScimEnterpriseUserJdbcRepository;

@Requires(property = "micronaut.security.scim.data.dialect", value = "H2")
@JdbcRepository(dialect = Dialect.H2)
public interface H2ScimEnterpriseUserJdbcRepository extends ScimEnterpriseUserJdbcRepository {
}
