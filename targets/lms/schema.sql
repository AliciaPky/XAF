-- XAF vulnerable LMS — seed schema
-- Loaded automatically by the MySQL container on first start.

CREATE DATABASE IF NOT EXISTS lms;
USE lms;

CREATE TABLE IF NOT EXISTS users (
    id        INT AUTO_INCREMENT PRIMARY KEY,
    username  VARCHAR(64)  NOT NULL UNIQUE,
    password  VARCHAR(128) NOT NULL,   -- plaintext on purpose (test target)
    full_name VARCHAR(128) NOT NULL,
    role      VARCHAR(32)  NOT NULL DEFAULT 'student'
);

CREATE TABLE IF NOT EXISTS courses (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    code       VARCHAR(16)  NOT NULL,
    title      VARCHAR(128) NOT NULL,
    instructor VARCHAR(128) NOT NULL
);

CREATE TABLE IF NOT EXISTS enrollments (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    student_id INT NOT NULL,
    course_id  INT NOT NULL,
    grade      VARCHAR(4) NOT NULL DEFAULT 'N/A',
    FOREIGN KEY (student_id) REFERENCES users(id),
    FOREIGN KEY (course_id)  REFERENCES courses(id)
);

INSERT INTO users (username, password, full_name, role) VALUES
    ('admin',    'S3cr3tAdmin!', 'System Administrator', 'admin'),
    ('student1', 'pass123',      'Brendy Yap',         'student'),
    ('student2', 'qwerty',       'Sash Shankar',           'student'),
    ('lecturer', 'teach2026',    'Dr. Hanis Jenalis',    'lecturer');

INSERT INTO courses (code, title, instructor) VALUES
    ('CS101', 'Introduction to Programming', 'Dr. Hanis Jenalis'),
    ('CS205', 'Database Systems',            'Dr. Hanis Jenalis'),
    ('CS310', 'Web Application Security',    'Dr. Hanis Jenalis'),
    ('CS320', 'Cloud Computing',             'Dr. Yusof Akmal');

INSERT INTO enrollments (student_id, course_id, grade) VALUES
    (2, 1, 'A'),
    (2, 2, 'B+'),
    (2, 3, 'A-'),
    (3, 1, 'B'),
    (3, 4, 'C+');
