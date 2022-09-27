CREATE DATABASE findhackedaccountdb;
CREATE USER 'findhackermng'@'%' IDENTIFIED BY 'fh_2011$_';
GRANT ALL PRIVILEGES ON *.findhackerdb TO 'findhackermng'@'%';

CREATE TABLE notification (
    id int NOT NULL AUTO_INCREMENT,
    date Datetime,
    email varchar(50),
    alt_email varchar(50),
    pass_changed_time bigint(200),
    notified varchar(5),
    PRIMARY KEY (id),
    KEY (id)
);

CREATE TABLE tracking (
    id int NOT NULL AUTO_INCREMENT,
    session bigint(2000),
    date Datetime,
    email varchar(50), 
    sent_count int,
    login_count int,
    dest_bad_count int,
    verified varchar(3),
    PRIMARY KEY (id),
    KEY (id)
);

