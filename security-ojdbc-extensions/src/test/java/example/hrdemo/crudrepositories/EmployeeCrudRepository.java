package example.hrdemo.crudrepositories;

import example.hrdemo.entities.EmployeeEntity;
import example.hrdemo.model.Employee;
import example.hrdemo.model.User;
import io.micronaut.data.annotation.Query;
import io.micronaut.data.annotation.Repository;
import io.micronaut.data.jdbc.annotation.JdbcRepository;
import io.micronaut.data.model.query.builder.sql.Dialect;
import io.micronaut.data.repository.CrudRepository;

import java.security.Principal;
import java.util.List;
import java.util.Optional;

@Repository
@JdbcRepository(dialect = Dialect.ORACLE)
public interface EmployeeCrudRepository extends CrudRepository<EmployeeEntity, Long> {
    Optional<Employee> findByEmployeeId(Long employeeId);

    @Query(nativeQuery = true, value = """
 SELECT e.manager_id
 FROM employees e
 START WITH e.employee_id = :employeeId
 CONNECT BY PRIOR e.manager_id = e.employee_id
 AND e.manager_id IS NOT NULL
 ORDER BY LEVEL""")
    List<Long> findAllManagersByEmployeeId(Long employeeId);

    @Query(nativeQuery = true, value = """
SELECT CASE
         WHEN EXISTS (
           SELECT 1
           FROM employees e
           WHERE e.user_name = :userName
           AND e.employee_id IN (
             SELECT e2.manager_id
             FROM employees e2
             START WITH e2.employee_id = :employeeId
             CONNECT BY PRIOR e2.manager_id = e2.employee_id
             AND e2.manager_id IS NOT NULL
           )
         ) THEN 1
         ELSE 0
       END
FROM dual""")
    boolean isManagerOfEmployee(String userName, Long employeeId);

    default boolean isManagerOfEmployee(Principal principal, Long employeeId) {
        return isManagerOfEmployee(principal.getName(), employeeId);
    }

    @Query("select employee_id as id, user_name as name from employees where user_name = :userName")
    Optional<User> findByUserName(String userName);

    default Optional<User> findUser(Principal principal) {
        return  findByUserName(principal.getName());
    }

}
