BEGIN
  DELETE FROM emp_timecards;
  DELETE FROM performance_goals;
  DELETE FROM emp_beneficiaries;
  DELETE FROM emp_contact_details;
  DELETE FROM emp_paystubs;
  DELETE FROM managers;
  DELETE FROM employees;
  DELETE FROM job_definitions;
  DELETE FROM departments;

  COMMIT;
END;
