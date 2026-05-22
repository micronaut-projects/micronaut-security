BEGIN
  INSERT INTO departments VALUES (1, 'Engineering', 'Engineering Department');
  INSERT INTO departments VALUES (2, 'HR', 'Human Resources Department');
  INSERT INTO departments VALUES (3, 'QA', 'Quality Assurance Department');

  INSERT INTO job_definitions VALUES ('SWE1', 'Software Engineer I', 'Entry-level software engineer', 'IC');
  INSERT INTO job_definitions VALUES ('SWE2', 'Software Engineer II', 'Mid-level software engineer', 'IC');
  INSERT INTO job_definitions VALUES ('SWE3', 'Senior Software Engineer', 'Senior level engineer', 'IC');
  INSERT INTO job_definitions VALUES ('SWE_LEAD', 'Lead Software Engineer', 'Leads engineering projects', 'IC');
  INSERT INTO job_definitions VALUES ('SWE_MGR', 'Engineering Manager', 'Manages engineering team', 'MANAGER');
  INSERT INTO job_definitions VALUES ('ENG_VP', 'Vice President of Engineering', 'Leads engineering and QA department', 'MANAGER');
  INSERT INTO job_definitions VALUES ('HR_REP', 'HR Specialist', 'Handles HR tasks', 'HR');
  INSERT INTO job_definitions VALUES ('HR_MGR', 'HR Manager', 'Manages HR department', 'MANAGER');
  INSERT INTO job_definitions VALUES ('HR_DIR', 'HR Director', 'Leads HR division', 'MANAGER');
  INSERT INTO job_definitions VALUES ('QA_MGR', 'QA Manager', 'Manages QA team', 'MANAGER');
  INSERT INTO job_definitions VALUES ('QA1', 'QA Analyst I', 'Entry-level QA analyst', 'IC');
  INSERT INTO job_definitions VALUES ('QA2', 'QA Analyst II', 'Mid-level QA analyst', 'IC');
  INSERT INTO job_definitions VALUES ('CEO', 'Chief Executive Officer', 'Company CEO', 'MANAGER');

  INSERT INTO employees VALUES (10, 'Cecilia', 'Young', 'CEO', NULL, 'xxxxxxxxx', NULL, 235000, 'CECILIA', NULL);
  INSERT INTO employees VALUES (11, 'Victoria', 'Williams', 'ENG_VP', 1, 'xxxxxxxxx', NULL, 205000, 'VICTORIA', 10);
  INSERT INTO employees VALUES (1, 'Marvin', 'Anderson', 'SWE_MGR', 1, 'xxxxxxxxx', NULL, 175000, 'MARVIN', 11);
  INSERT INTO employees VALUES (2, 'Linda', 'Smith', 'QA_MGR', 3, 'xxxxxxxxx', NULL, 145000, 'LINDA', 11);
  INSERT INTO employees VALUES (3, 'Emma', 'Baker', 'SWE2', 1, 'xxxxxxxxx', NULL, 120000, 'EMMA', 1);
  INSERT INTO employees VALUES (4, 'Alex', 'Johnson', 'SWE2', 1, 'xxxxxxxxx', NULL, 115000, 'ALEX', 1);
  INSERT INTO employees VALUES (5, 'Chris', 'Evans', 'SWE1', 1, 'xxxxxxxxx', NULL, 95000, 'CHRIS', 1);
  INSERT INTO employees VALUES (6, 'Taylor', 'Mills', 'SWE3', 1, 'xxxxxxxxx', NULL, 130000, 'TAYLOR', 1);
  INSERT INTO employees VALUES (7, 'Morgan', 'Lee', 'QA1', 3, 'xxxxxxxxx', NULL, 99000, 'MORGAN', 2);
  INSERT INTO employees VALUES (8, 'Jordan', 'Parks', 'QA2', 3, 'xxxxxxxxx', NULL, 109000, 'JORDAN', 2);
  INSERT INTO employees VALUES (9, 'Henry', 'Wong', 'HR_REP', 2, 'xxxxxxxxx', NULL, 92000, 'HENRY', 10);

  FOR rec IN (SELECT employee_id FROM employees) LOOP
    UPDATE employees
    SET ssn = LPAD(TRUNC(DBMS_RANDOM.VALUE(100, 999)), 3, '0') || '-' ||
              LPAD(TRUNC(DBMS_RANDOM.VALUE(10, 99)), 2, '0') || '-' ||
              LPAD(TRUNC(DBMS_RANDOM.VALUE(1000, 9999)), 4, '0')
    WHERE employee_id = rec.employee_id;
  END LOOP;

  INSERT INTO managers (manager_id, employee_id, mgr_user_name, mgr_first_name, mgr_last_name)
  SELECT e.manager_id, e.employee_id, m.user_name, m.first_name, m.last_name
  FROM employees e
  JOIN employees m ON e.manager_id = m.employee_id
  WHERE e.manager_id IS NOT NULL;

  INSERT INTO emp_paystubs VALUES (9101, 1, TO_DATE('2025-07-16','YYYY-MM-DD'), TO_DATE('2025-07-31','YYYY-MM-DD'), 14583.33, 10500.00, 2916.67, 1166.66, TO_DATE('2025-08-01','YYYY-MM-DD'), 'xxxxxxx1111');
  INSERT INTO emp_paystubs VALUES (9102, 1, TO_DATE('2025-08-16','YYYY-MM-DD'), TO_DATE('2025-08-31','YYYY-MM-DD'), 14583.33, 10500.00, 2916.67, 1166.66, TO_DATE('2025-09-01','YYYY-MM-DD'), 'xxxxxxx1111');
  INSERT INTO emp_paystubs VALUES (9103, 1, TO_DATE('2025-09-16','YYYY-MM-DD'), TO_DATE('2025-09-30','YYYY-MM-DD'), 14583.33, 10500.00, 2916.67, 1166.66, TO_DATE('2025-10-01','YYYY-MM-DD'), 'xxxxxxx1111');
  INSERT INTO emp_paystubs VALUES (9201, 2, TO_DATE('2025-07-16','YYYY-MM-DD'), TO_DATE('2025-07-31','YYYY-MM-DD'), 12083.33, 8700.00, 2416.67, 966.66, TO_DATE('2025-08-01','YYYY-MM-DD'), 'xxxxxxx2222');
  INSERT INTO emp_paystubs VALUES (9202, 2, TO_DATE('2025-08-16','YYYY-MM-DD'), TO_DATE('2025-08-31','YYYY-MM-DD'), 12083.33, 8700.00, 2416.67, 966.66, TO_DATE('2025-09-01','YYYY-MM-DD'), 'xxxxxxx2222');
  INSERT INTO emp_paystubs VALUES (9203, 2, TO_DATE('2025-09-16','YYYY-MM-DD'), TO_DATE('2025-09-30','YYYY-MM-DD'), 12083.33, 8700.00, 2416.67, 966.66, TO_DATE('2025-10-01','YYYY-MM-DD'), 'xxxxxxx2222');
  INSERT INTO emp_paystubs VALUES (9301, 3, TO_DATE('2025-07-16','YYYY-MM-DD'), TO_DATE('2025-07-31','YYYY-MM-DD'), 10000.00, 7200.00, 2000.00, 800.00, TO_DATE('2025-08-01','YYYY-MM-DD'), 'xxxxxxx3333');
  INSERT INTO emp_paystubs VALUES (9302, 3, TO_DATE('2025-08-16','YYYY-MM-DD'), TO_DATE('2025-08-31','YYYY-MM-DD'), 10000.00, 7200.00, 2000.00, 800.00, TO_DATE('2025-09-01','YYYY-MM-DD'), 'xxxxxxx3333');
  INSERT INTO emp_paystubs VALUES (9303, 3, TO_DATE('2025-09-16','YYYY-MM-DD'), TO_DATE('2025-09-30','YYYY-MM-DD'), 10000.00, 7200.00, 2000.00, 800.00, TO_DATE('2025-10-01','YYYY-MM-DD'), 'xxxxxxx3333');
  INSERT INTO emp_paystubs VALUES (9401, 4, TO_DATE('2025-07-16','YYYY-MM-DD'), TO_DATE('2025-07-31','YYYY-MM-DD'), 9583.33, 6900.00, 1916.67, 766.66, TO_DATE('2025-08-01','YYYY-MM-DD'), 'xxxxxxx4444');
  INSERT INTO emp_paystubs VALUES (9402, 4, TO_DATE('2025-08-16','YYYY-MM-DD'), TO_DATE('2025-08-31','YYYY-MM-DD'), 9583.33, 6900.00, 1916.67, 766.66, TO_DATE('2025-09-01','YYYY-MM-DD'), 'xxxxxxx4444');
  INSERT INTO emp_paystubs VALUES (9403, 4, TO_DATE('2025-09-16','YYYY-MM-DD'), TO_DATE('2025-09-30','YYYY-MM-DD'), 9583.33, 6900.00, 1916.67, 766.66, TO_DATE('2025-10-01','YYYY-MM-DD'), 'xxxxxxx4444');
  INSERT INTO emp_paystubs VALUES (9501, 5, TO_DATE('2025-07-16','YYYY-MM-DD'), TO_DATE('2025-07-31','YYYY-MM-DD'), 7916.67, 5700.00, 1583.33, 633.33, TO_DATE('2025-08-01','YYYY-MM-DD'), 'xxxxxxx5555');
  INSERT INTO emp_paystubs VALUES (9502, 5, TO_DATE('2025-08-16','YYYY-MM-DD'), TO_DATE('2025-08-31','YYYY-MM-DD'), 7916.67, 5700.00, 1583.33, 633.33, TO_DATE('2025-09-01','YYYY-MM-DD'), 'xxxxxxx5555');
  INSERT INTO emp_paystubs VALUES (9503, 5, TO_DATE('2025-09-16','YYYY-MM-DD'), TO_DATE('2025-09-30','YYYY-MM-DD'), 7916.67, 5700.00, 1583.33, 633.33, TO_DATE('2025-10-01','YYYY-MM-DD'), 'xxxxxxx5555');
  INSERT INTO emp_paystubs VALUES (9601, 6, TO_DATE('2025-07-16','YYYY-MM-DD'), TO_DATE('2025-07-31','YYYY-MM-DD'), 10833.33, 7800.00, 2166.67, 866.66, TO_DATE('2025-08-01','YYYY-MM-DD'), 'xxxxxxx6666');
  INSERT INTO emp_paystubs VALUES (9602, 6, TO_DATE('2025-08-16','YYYY-MM-DD'), TO_DATE('2025-08-31','YYYY-MM-DD'), 10833.33, 7800.00, 2166.67, 866.66, TO_DATE('2025-09-01','YYYY-MM-DD'), 'xxxxxxx6666');
  INSERT INTO emp_paystubs VALUES (9603, 6, TO_DATE('2025-09-16','YYYY-MM-DD'), TO_DATE('2025-09-30','YYYY-MM-DD'), 10833.33, 7800.00, 2166.67, 866.66, TO_DATE('2025-10-01','YYYY-MM-DD'), 'xxxxxxx6666');
  INSERT INTO emp_paystubs VALUES (9701, 7, TO_DATE('2025-07-16','YYYY-MM-DD'), TO_DATE('2025-07-31','YYYY-MM-DD'), 8250.00, 5980.00, 1650.00, 620.00, TO_DATE('2025-08-01','YYYY-MM-DD'), 'xxxxxxx7777');
  INSERT INTO emp_paystubs VALUES (9702, 7, TO_DATE('2025-08-16','YYYY-MM-DD'), TO_DATE('2025-08-31','YYYY-MM-DD'), 8250.00, 5980.00, 1650.00, 620.00, TO_DATE('2025-09-01','YYYY-MM-DD'), 'xxxxxxx7777');
  INSERT INTO emp_paystubs VALUES (9703, 7, TO_DATE('2025-09-16','YYYY-MM-DD'), TO_DATE('2025-09-30','YYYY-MM-DD'), 8250.00, 5980.00, 1650.00, 620.00, TO_DATE('2025-10-01','YYYY-MM-DD'), 'xxxxxxx7777');
  INSERT INTO emp_paystubs VALUES (9801, 8, TO_DATE('2025-07-16','YYYY-MM-DD'), TO_DATE('2025-07-31','YYYY-MM-DD'), 9083.33, 6580.00, 1816.67, 686.66, TO_DATE('2025-08-01','YYYY-MM-DD'), 'xxxxxxx8888');
  INSERT INTO emp_paystubs VALUES (9802, 8, TO_DATE('2025-08-16','YYYY-MM-DD'), TO_DATE('2025-08-31','YYYY-MM-DD'), 9083.33, 6580.00, 1816.67, 686.66, TO_DATE('2025-09-01','YYYY-MM-DD'), 'xxxxxxx8888');
  INSERT INTO emp_paystubs VALUES (9803, 8, TO_DATE('2025-09-16','YYYY-MM-DD'), TO_DATE('2025-09-30','YYYY-MM-DD'), 9083.33, 6580.00, 1816.67, 686.66, TO_DATE('2025-10-01','YYYY-MM-DD'), 'xxxxxxx8888');
  INSERT INTO emp_paystubs VALUES (9901, 9, TO_DATE('2025-07-16','YYYY-MM-DD'), TO_DATE('2025-07-31','YYYY-MM-DD'), 7666.67, 5550.00, 1533.33, 613.34, TO_DATE('2025-08-01','YYYY-MM-DD'), 'xxxxxxx9999');
  INSERT INTO emp_paystubs VALUES (9902, 9, TO_DATE('2025-08-16','YYYY-MM-DD'), TO_DATE('2025-08-31','YYYY-MM-DD'), 7666.67, 5550.00, 1533.33, 613.34, TO_DATE('2025-09-01','YYYY-MM-DD'), 'xxxxxxx9999');
  INSERT INTO emp_paystubs VALUES (9903, 9, TO_DATE('2025-09-16','YYYY-MM-DD'), TO_DATE('2025-09-30','YYYY-MM-DD'), 7666.67, 5550.00, 1533.33, 613.34, TO_DATE('2025-10-01','YYYY-MM-DD'), 'xxxxxxx9999');
  INSERT INTO emp_paystubs VALUES (10001, 10, TO_DATE('2025-07-16','YYYY-MM-DD'), TO_DATE('2025-07-31','YYYY-MM-DD'), 19583.33, 14100.00, 3916.67, 1566.66, TO_DATE('2025-08-01','YYYY-MM-DD'), 'xxxxxxx0000');
  INSERT INTO emp_paystubs VALUES (10002, 10, TO_DATE('2025-08-16','YYYY-MM-DD'), TO_DATE('2025-08-31','YYYY-MM-DD'), 19583.33, 14100.00, 3916.67, 1566.66, TO_DATE('2025-09-01','YYYY-MM-DD'), 'xxxxxxx0000');
  INSERT INTO emp_paystubs VALUES (10003, 10, TO_DATE('2025-09-16','YYYY-MM-DD'), TO_DATE('2025-09-30','YYYY-MM-DD'), 19583.33, 14100.00, 3916.67, 1566.66, TO_DATE('2025-10-01','YYYY-MM-DD'), 'xxxxxxx0000');
  INSERT INTO emp_paystubs VALUES (11001, 11, TO_DATE('2025-07-16','YYYY-MM-DD'), TO_DATE('2025-07-31','YYYY-MM-DD'), 17083.33, 12300.00, 3416.67, 1366.66, TO_DATE('2025-08-01','YYYY-MM-DD'), 'xxxxxxx1011');
  INSERT INTO emp_paystubs VALUES (11002, 11, TO_DATE('2025-08-16','YYYY-MM-DD'), TO_DATE('2025-08-31','YYYY-MM-DD'), 17083.33, 12300.00, 3416.67, 1366.66, TO_DATE('2025-09-01','YYYY-MM-DD'), 'xxxxxxx1011');
  INSERT INTO emp_paystubs VALUES (11003, 11, TO_DATE('2025-09-16','YYYY-MM-DD'), TO_DATE('2025-09-30','YYYY-MM-DD'), 17083.33, 12300.00, 3416.67, 1366.66, TO_DATE('2025-10-01','YYYY-MM-DD'), 'xxxxxxx1011');

  INSERT INTO emp_contact_details VALUES (1, 'HOME', 'marvin.anderson.home@xxxxxxxxx.com', '(515) 123-4567', '2001 Applewood Ct, Southlake, TX, 75001');
  INSERT INTO emp_contact_details VALUES (1, 'WORK', 'marvin.anderson@az510oracleoutlook.onmicrosoft.com', '(650) 505-1876', '2014 Jabberwocky Rd, Southlake, TX, 26192');
  INSERT INTO emp_contact_details VALUES (2, 'HOME', 'linda.smith.home@xxxxxxxxx.com', '(515) 123-4568', '101 Oak Rd, South San Francisco, CA, 94080');
  INSERT INTO emp_contact_details VALUES (2, 'WORK', 'linda.smith@az510oracleoutlook.onmicrosoft.com', '(650) 505-2876', '2011 Interiors Blvd, South San Francisco, CA, 99236');
  INSERT INTO emp_contact_details VALUES (3, 'HOME', 'emma.baker.home@xxxxxxxxx.com', '(515) 123-4569', '202 Maple St, Austin, TX, 75002');
  INSERT INTO emp_contact_details VALUES (3, 'WORK', 'emma.baker@az510oracleoutlook.onmicrosoft.com', '(650) 505-3876', '2014 Jabberwocky Rd, Southlake, TX, 26192');
  INSERT INTO emp_contact_details VALUES (4, 'HOME', 'alex.johnson.home@xxxxxxxxx.com', '(590) 423-4567', '203 Birch Ave, Dallas, TX, 75003');
  INSERT INTO emp_contact_details VALUES (4, 'WORK', 'alex.johnson@az510oracleoutlook.onmicrosoft.com', '(650) 505-4876', '2014 Jabberwocky Rd, Southlake, TX, 26192');
  INSERT INTO emp_contact_details VALUES (5, 'HOME', 'chris.evans.home@xxxxxxxxx.com', '(590) 423-4568', '204 Cedar Ct, Plano, TX, 75004');
  INSERT INTO emp_contact_details VALUES (5, 'WORK', 'chris.evans@az510oracleoutlook.onmicrosoft.com', '(650) 501-1876', '2014 Jabberwocky Rd, Southlake, TX, 26192');
  INSERT INTO emp_contact_details VALUES (6, 'HOME', 'taylor.mills.home@xxxxxxxxx.com', '(590) 423-4569', '205 Willow Rd, Houston, TX, 75005');
  INSERT INTO emp_contact_details VALUES (6, 'WORK', 'taylor.mills@az510oracleoutlook.onmicrosoft.com', '(650) 501-3876', '2014 Jabberwocky Rd, Southlake, TX, 26192');
  INSERT INTO emp_contact_details VALUES (7, 'HOME', 'morgan.lee.home@xxxxxxxxx.com', '(590) 423-4560', '932 Spruce St, San Mateo, CA, 94081');
  INSERT INTO emp_contact_details VALUES (7, 'WORK', 'morgan.lee@az510oracleoutlook.onmicrosoft.com', '(650) 501-4876', '2011 Interiors Blvd, South San Francisco, CA, 99236');
  INSERT INTO emp_contact_details VALUES (8, 'HOME', 'jordan.parks.home@xxxxxxxxx.com', '(590) 423-5567', '103 Elm St, Burlingame, CA, 94082');
  INSERT INTO emp_contact_details VALUES (8, 'WORK', 'jordan.parks@az510oracleoutlook.onmicrosoft.com', '(650) 507-9811', '2011 Interiors Blvd, South San Francisco, CA, 99236');
  INSERT INTO emp_contact_details VALUES (9, 'HOME', 'henry.wong.home@xxxxxxxxx.com', '(515) 124-4569', '104 Aspen Ln, Fremont, CA, 94083');
  INSERT INTO emp_contact_details VALUES (9, 'WORK', 'henry.wong@az510oracleoutlook.onmicrosoft.com', '(650) 507-9822', '2011 Interiors Blvd, South San Francisco, CA, 99236');
  INSERT INTO emp_contact_details VALUES (10, 'HOME', 'cecilia.young.home@xxxxxxxxx.com', '(515) 124-4169', '105 Fir Dr, Palo Alto, CA, 94084');
  INSERT INTO emp_contact_details VALUES (10, 'WORK', 'cecilia.young@az510oracleoutlook.onmicrosoft.com', '(650) 507-9833', '2011 Interiors Blvd, South San Francisco, CA, 99236');
  INSERT INTO emp_contact_details VALUES (11, 'HOME', 'victoria.williams.home@xxxxxxxxx.com', '(515) 123-8181', '203 Forest St, Palo Alto, CA, 94084');
  INSERT INTO emp_contact_details VALUES (11, 'WORK', 'victoria.williams@az510oracleoutlook.onmicrosoft.com', '(650) 507-9844', '2011 Interiors Blvd, South San Francisco, CA, 99236');

  INSERT INTO emp_beneficiaries VALUES (1, 1, 'Alice', 'Anderson', 'Spouse');
  INSERT INTO emp_beneficiaries VALUES (2, 1, 'Sam', 'Anderson', 'Child');
  INSERT INTO emp_beneficiaries VALUES (3, 2, 'Bob', 'Smith', 'Spouse');
  INSERT INTO emp_beneficiaries VALUES (4, 3, 'Ella', 'Baker', 'Spouse');
  INSERT INTO emp_beneficiaries VALUES (5, 3, 'Mia', 'Baker', 'Child');
  INSERT INTO emp_beneficiaries VALUES (6, 5, 'Jordan', 'Evans', 'Parent');
  INSERT INTO emp_beneficiaries VALUES (7, 8, 'Taylor', 'Parks', 'Parent');
  INSERT INTO emp_beneficiaries VALUES (8, 10, 'Daniel', 'Young', 'Spouse');
  INSERT INTO emp_beneficiaries VALUES (9, 10, 'Olivia', 'Young', 'Child');

  INSERT INTO performance_goals VALUES (1002, 1, 'Promote Team Growth', 2024, 'Mentor engineers and help them level up their skills.', 'Held multiple knowledge sharing sessions.', 'Positive feedback from the team.', 'Great culture impact.', 5, 4, 'Completed');
  INSERT INTO performance_goals VALUES (1001, 1, 'Lead Engineering Team', 2025, 'Lead migration of core services to cloud', 'Phase 1 completed, phase 2 in progress.', NULL, NULL, 5, NULL, 'Self Evaluation');
  INSERT INTO performance_goals VALUES (1003, 2, 'Enhance QA Processes', 2024, 'Lead QA strategy and implement efficient testing processes.', 'Reviewed current QA procedures and recommended improvements.', 'Implemented automation framework for regression testing.', 'Great at team coordination and reporting.', 5, 5, 'Completed');
  INSERT INTO performance_goals VALUES (1004, 2, 'Reduce Defect Leakage', 2025, 'Introduce new quality checkpoints to minimize defects escaping to production.', 'Analyzed root causes of previous escaped defects.', 'Set up new review gates and monitoring alerts.', 'Much improved defect metrics.', 5, 4, 'Manager Evaluation');
  INSERT INTO performance_goals VALUES (1005, 3, 'Deliver Feature Y', 2024, 'Take ownership of Feature Y development and deployment.', 'Achieved significant progress ahead of schedule.', 'Exceptional code quality and fast delivery.', 'Private: Consistently exceeded coding standards.', 4, 5, 'Completed');
  INSERT INTO performance_goals VALUES (1006, 3, 'ACME Crop. HR application project', 2025, 'Deliver ACME Crop. HR application project.', 'Currently on track to deliver the project.', 'Emma has shown consistent progress.', 'Much improved defect metrics.', 5, 4, 'Manager Evaluation');
  INSERT INTO performance_goals VALUES (1007, 4, 'Optimize Build Pipeline', 2025, 'Implement enhancements to CI/CD pipelines for reliability.', 'Reduced build failures by optimizing configurations.', NULL, NULL, 4, NULL, 'Self Evaluation');
  INSERT INTO performance_goals VALUES (1008, 5, 'Refactor Legacy Module X', 2024, 'Help the team improve maintainability by refactoring Module X.', 'Took the initiative to redesign critical code paths.', 'Helped reduce technical debt.', 'Good progress for first major project.', 4, 4, 'Completed');
  INSERT INTO performance_goals VALUES (1009, 5, 'Team Knowledge Sharing', 2025, 'Share engineering knowledge through team presentations.', 'Organized and presented 2 tech talks.', NULL, NULL, 5, NULL, 'Self Evaluation');
  INSERT INTO performance_goals VALUES (1010, 6, 'Mentor New Hires', 2025, 'Guide onboarding for new software engineers.', 'Helped onboard 3 new team members successfully.', 'Positive feedback from mentees.', 'Essential in reducing onboarding time.', 5, 5, 'Manager Evaluation');
  INSERT INTO performance_goals VALUES (1011, 7, 'Automate Functional Tests', 2024, 'Create automated scripts for functional UI tests.', 'Developed automation using Selenium.', 'Tests now run nightly with alerts on failure.', 'Good attention to edge case scenarios.', 5, 5, 'Completed');
  INSERT INTO performance_goals VALUES (1012, 7, 'Improve Test Documentation', 2025, 'Update and expand QA documentation for test scenarios.', 'Added missing test cases and updated wiki.', 'More onboarding material for interns now available.', 'Documentation up-to-date and thorough.', 4, 4, 'Manager Evaluation');
  INSERT INTO performance_goals VALUES (1013, 8, 'Streamline Regression Cycle', 2025, 'Reduce regression cycle time through selective test execution.', 'Analyzed slow tests and optimized test set.', 'Regressions now complete 30% faster.', 'Improved sprint release times.', 4, 5, 'Manager Evaluation');
  INSERT INTO performance_goals VALUES (1016, 11, 'Expand Engineering Team Capabilities', 2024, 'Recruit and onboard top engineering talent to support growth objectives.', 'Interviewed several strong candidates; onboarding in progress.', 'Proactive hiring has reduced project risk.', 'Excellent engagement with candidates and new hires.', 4, 5, 'Completed');
  INSERT INTO performance_goals VALUES (1017, 11, 'Drive Cross-Department Collaboration', 2025, 'Promote effective collaboration between Engineering and QA/Human Resources.', 'Established joint task forces and hosted regular alignment meetings.', 'Improved communication between departments.', 'Initiative has led to smoother project handoffs.', 5, 5, 'Completed');
  INSERT INTO performance_goals VALUES (1018, 9, 'Improve Onboarding Experience', 2024, 'Revamp the onboarding process to reduce time-to-productivity for new employees.', 'Collected feedback from recent hires and updated onboarding materials.', 'Managers reported faster ramp-up times for new employees.', 'Privately noted that further automation could be explored.', 5, 4, 'Completed');
  INSERT INTO performance_goals VALUES (1019, 9, 'Enhance Employee Wellness Program', 2025, 'Expand and promote wellness resources and engagement initiatives.', 'Launched monthly wellness events and quarterly health talks.', 'Positive feedback on event variety and participation.', 'Some events had lower turnout—identified improvement areas.', 4, 4, 'Completed');

  INSERT INTO emp_timecards VALUES (DATE '2025-09-01', 1, 8,'Work',8,'Work',10,'Work',6,'Work',8,'Time off',NULL,NULL,NULL,NULL,'Submitted');
  INSERT INTO emp_timecards VALUES (DATE '2025-09-08', 1, 8,'Work',8,'Work',8,'Work',8,'Work',8,'Work',NULL,NULL,NULL,NULL,'Submitted');
  INSERT INTO emp_timecards VALUES (DATE '2025-09-15', 1, 8,'Work',8,'Work',8,'Work',8,'Work',8,'Work',NULL,NULL,NULL,NULL,'Submitted');
  INSERT INTO emp_timecards VALUES (DATE '2025-09-22', 1, 8,'Work',8,'Work',8,'Work',8,'Work',8,'Time off',NULL,NULL,NULL,NULL,'Submitted');
  INSERT INTO emp_timecards VALUES (DATE '2025-09-01', 2, 8,'Work',8,'Work',8,'Work',8,'Work',8,'Work',NULL,NULL,NULL,NULL,'Submitted');
  INSERT INTO emp_timecards VALUES (DATE '2025-09-08', 2, 8,'Work',8,'Work',8,'Work',8,'Work',8,'Work',NULL,NULL,NULL,NULL,'Submitted');
  INSERT INTO emp_timecards VALUES (DATE '2025-09-15', 2, 8,'Time off',8,'Work',8,'Work',8,'Work',8,'Work',NULL,NULL,NULL,NULL,'Submitted');
  INSERT INTO emp_timecards VALUES (DATE '2025-09-22', 2, 8,'Work',8,'Work',8,'Work',8,'Work',8,'Work',NULL,NULL,NULL,NULL,'Submitted');
  INSERT INTO emp_timecards VALUES (DATE '2025-09-01', 3, 8,'Time off',8,'Time off',10,'Work',6,'Work',8,'Work',NULL,NULL,NULL,NULL,'Submitted');
  INSERT INTO emp_timecards VALUES (DATE '2025-09-08', 3, 8,'Work',8,'Work',8,'Work',8,'Work',8,'Work',NULL,NULL,NULL,NULL,'Submitted');
  INSERT INTO emp_timecards VALUES (DATE '2025-09-15', 3, 8,'Work',8,'Work',8,'Work',8,'Work',8,'Work',NULL,NULL,NULL,NULL,'Submitted');
  INSERT INTO emp_timecards VALUES (DATE '2025-09-22', 3, 8,'Time off',8,'Time off',8,'Work',8,'Work',8,'Work',NULL,NULL,NULL,NULL,'Submitted');
  INSERT INTO emp_timecards VALUES (DATE '2025-09-01', 4, 8,'Work',8,'Work',8,'Work',8,'Work',8,'Work',NULL,NULL,NULL,NULL,'Submitted');
  INSERT INTO emp_timecards VALUES (DATE '2025-09-08', 4, 8,'Work',8,'Work',8,'Work',8,'Work',8,'Work',NULL,NULL,NULL,NULL,'Submitted');
  INSERT INTO emp_timecards VALUES (DATE '2025-09-15', 4, 8,'Work',8,'Work',8,'Work',8,'Work',8,'Work',NULL,NULL,NULL,NULL,'Submitted');
  INSERT INTO emp_timecards VALUES (DATE '2025-09-22', 4, 8,'Work',8,'Work',8,'Work',8,'Work',8,'Work',NULL,NULL,NULL,NULL,'Submitted');
  INSERT INTO emp_timecards VALUES (DATE '2025-09-01', 5, 8,'Work',8,'Work',8,'Work',8,'Work',8,'Work',NULL,NULL,NULL,NULL,'Submitted');
  INSERT INTO emp_timecards VALUES (DATE '2025-09-08', 5, 8,'Work',8,'Work',8,'Work',8,'Work',8,'Work',NULL,NULL,NULL,NULL,'Submitted');
  INSERT INTO emp_timecards VALUES (DATE '2025-09-15', 5, 8,'Work',8,'Work',8,'Work',8,'Work',8,'Work',NULL,NULL,NULL,NULL,'Submitted');
  INSERT INTO emp_timecards VALUES (DATE '2025-09-22', 5, 8,'Work',8,'Work',8,'Work',8,'Work',8,'Work',NULL,NULL,NULL,NULL,'Submitted');
  INSERT INTO emp_timecards VALUES (DATE '2025-09-01', 6, 8,'Work',8,'Work',8,'Work',8,'Work',8,'Work',NULL,NULL,NULL,NULL,'Submitted');
  INSERT INTO emp_timecards VALUES (DATE '2025-09-08', 6, 8,'Work',8,'Work',8,'Work',8,'Work',8,'Work',NULL,NULL,NULL,NULL,'Submitted');
  INSERT INTO emp_timecards VALUES (DATE '2025-09-15', 6, 8,'Work',8,'Work',8,'Work',8,'Work',8,'Work',NULL,NULL,NULL,NULL,'Submitted');
  INSERT INTO emp_timecards VALUES (DATE '2025-09-22', 6, 8,'Work',8,'Work',8,'Work',8,'Work',8,'Work',NULL,NULL,NULL,NULL,'Submitted');
  INSERT INTO emp_timecards VALUES (DATE '2025-09-01', 7, 8,'Work',8,'Work',8,'Work',8,'Work',8,'Work',NULL,NULL,NULL,NULL,'Submitted');
  INSERT INTO emp_timecards VALUES (DATE '2025-09-08', 7, 8,'Work',8,'Work',8,'Work',8,'Work',8,'Work',NULL,NULL,NULL,NULL,'Submitted');
  INSERT INTO emp_timecards VALUES (DATE '2025-09-15', 7, 8,'Work',8,'Work',8,'Work',8,'Work',8,'Work',NULL,NULL,NULL,NULL,'Submitted');
  INSERT INTO emp_timecards VALUES (DATE '2025-09-22', 7, 8,'Work',8,'Work',8,'Work',8,'Work',8,'Work',NULL,NULL,NULL,NULL,'Submitted');
  INSERT INTO emp_timecards VALUES (DATE '2025-09-01', 8, 8,'Work',8,'Work',8,'Work',8,'Work',8,'Work',NULL,NULL,NULL,NULL,'Submitted');
  INSERT INTO emp_timecards VALUES (DATE '2025-09-08', 8, 8,'Work',8,'Work',8,'Work',8,'Work',8,'Work',NULL,NULL,NULL,NULL,'Submitted');
  INSERT INTO emp_timecards VALUES (DATE '2025-09-15', 8, 8,'Time off',8,'Time off',8,'Time off',8,'Time off',8,'Time off',NULL,NULL,NULL,NULL,'Submitted');
  INSERT INTO emp_timecards VALUES (DATE '2025-09-22', 8, 8,'Work',8,'Work',8,'Work',8,'Work',8,'Work',NULL,NULL,NULL,NULL,'Submitted');
  INSERT INTO emp_timecards VALUES (DATE '2025-09-01', 9, 8,'Work',8,'Work',8,'Work',8,'Work',8,'Work',NULL,NULL,NULL,NULL,'Submitted');
  INSERT INTO emp_timecards VALUES (DATE '2025-09-08', 9, 8,'Work',8,'Work',8,'Work',8,'Work',8,'Work',NULL,NULL,NULL,NULL,'Submitted');
  INSERT INTO emp_timecards VALUES (DATE '2025-09-15', 9, 8,'Work',8,'Work',8,'Time off',8,'Work',8,'Work',NULL,NULL,NULL,NULL,'Submitted');
  INSERT INTO emp_timecards VALUES (DATE '2025-09-22', 9, 8,'Time off',8,'Work',8,'Work',8,'Work',8,'Work',NULL,NULL,NULL,NULL,'Submitted');
  INSERT INTO emp_timecards VALUES (DATE '2025-09-01', 10, 8,'Work',8,'Work',8,'Work',8,'Work',8,'Work',NULL,NULL,NULL,NULL,'Submitted');
  INSERT INTO emp_timecards VALUES (DATE '2025-09-08', 10, 8,'Work',8,'Work',8,'Work',8,'Work',8,'Work',NULL,NULL,NULL,NULL,'Submitted');
  INSERT INTO emp_timecards VALUES (DATE '2025-09-15', 10, 8,'Work',8,'Work',8,'Work',8,'Work',8,'Time off',NULL,NULL,NULL,NULL,'Submitted');
  INSERT INTO emp_timecards VALUES (DATE '2025-09-22', 10, 8,'Work',8,'Work',8,'Work',8,'Work',8,'Work',NULL,NULL,NULL,NULL,'Submitted');
  INSERT INTO emp_timecards VALUES (DATE '2025-09-01', 11, 8,'Work',8,'Work',8,'Work',8,'Work',8,'Work',NULL,NULL,NULL,NULL,'Submitted');
  INSERT INTO emp_timecards VALUES (DATE '2025-09-08', 11, 8,'Work',8,'Work',8,'Work',8,'Work',8,'Work',NULL,NULL,NULL,NULL,'Submitted');
  INSERT INTO emp_timecards VALUES (DATE '2025-09-15', 11, 8,'Work',8,'Work',8,'Work',8,'Work',8,'Work',NULL,NULL,NULL,NULL,'Submitted');
  INSERT INTO emp_timecards VALUES (DATE '2025-09-22', 11, 8,'Work',8,'Work',8,'Work',8,'Work',8,'Work',NULL,NULL,NULL,NULL,'Submitted');

  COMMIT;
END;
