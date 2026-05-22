package example.hrdemo.repositories;

import example.hrdemo.model.Employee;

import java.security.Principal;
import java.util.Optional;

public interface EmployeeRepository {
    Optional<Employee> findById(Principal principal, Long id);
}
