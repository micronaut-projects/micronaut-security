package io.micronaut.security.scim.data.jdbc.repositories.mysql;

import io.micronaut.context.annotation.Requires;
import io.micronaut.data.jdbc.annotation.JdbcRepository;
import io.micronaut.data.model.query.builder.sql.Dialect;
import io.micronaut.security.scim.data.jdbc.repositories.ScimEnterpriseUserJdbcRepository;

@Requires(property = "micronaut.security.scim.data.dialect", value = "MYSQL")
@JdbcRepository(dialect = Dialect.MYSQL)
public interface MySQLScimEnterpriseUserJdbcRepository extends ScimEnterpriseUserJdbcRepository {
}
