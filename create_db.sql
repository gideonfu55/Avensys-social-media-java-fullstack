DROP DATABASE IF EXISTS socialmediadb;
DROP USER IF EXISTS `socialmediaadmin`@`%`;
DROP USER IF EXISTS `socialmediauser`@`%`;
CREATE DATABASE IF NOT EXISTS socialmediadb CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS `socialmediaadmin`@`%` IDENTIFIED WITH mysql_native_password BY 'password';
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, REFERENCES, INDEX, ALTER, EXECUTE, CREATE VIEW, SHOW VIEW,
    CREATE ROUTINE, ALTER ROUTINE, EVENT, TRIGGER ON `socialmediadb`.* TO `socialmediaadmin`@`%`;
CREATE USER IF NOT EXISTS `socialmediauser`@`%` IDENTIFIED WITH mysql_native_password BY 'password';
GRANT SELECT, INSERT, UPDATE, DELETE, SHOW VIEW ON `socialmediadb`.* TO `socialmediauser`@`%`;
FLUSH PRIVILEGES;