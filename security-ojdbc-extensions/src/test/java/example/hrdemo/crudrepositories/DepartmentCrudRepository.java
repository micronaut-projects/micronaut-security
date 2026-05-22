package example.hrdemo.crudrepositories;

import example.hrdemo.entities.DepartmentEntity;
import io.micronaut.data.annotation.Repository;
import io.micronaut.data.jdbc.annotation.JdbcRepository;
import io.micronaut.data.model.query.builder.sql.Dialect;
import io.micronaut.data.repository.CrudRepository;

@Repository
@JdbcRepository(dialect = Dialect.ORACLE)
public interface DepartmentCrudRepository extends CrudRepository<DepartmentEntity, Long> {
}
