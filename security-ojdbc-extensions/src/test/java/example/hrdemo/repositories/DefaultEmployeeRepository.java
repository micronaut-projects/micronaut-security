package example.hrdemo.repositories;

import example.hrdemo.crudrepositories.EmployeeCrudRepository;
import example.hrdemo.model.Employee;
import jakarta.inject.Singleton;

import java.security.Principal;
import java.util.Optional;

@Singleton
class DefaultEmployeeRepository implements EmployeeRepository {
    private final EmployeeCrudRepository employeeCrudRepository;

    DefaultEmployeeRepository(EmployeeCrudRepository employeeCrudRepository) {
        this.employeeCrudRepository = employeeCrudRepository;
    }

    @Override
    public Optional<Employee> findById(Principal principal, Long id) {

        Optional<Employee> employeeOptional = employeeCrudRepository.findByEmployeeId(id);
        if (employeeOptional.isEmpty()) {
            return Optional.empty();
        }
        Employee employee = employeeOptional.get();
        if (employeeCrudRepository.isManagerOfEmployee(principal, id)) {
            return Optional.of(employee);
        }
        return Optional.of(new Employee(employee.employeeId(), employee.firstName(), employee.lastName(), null));
    }
}
