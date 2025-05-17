DROP TABLE IF EXISTS logfile;

CREATE TABLE logfile (
    ip VARCHAR(45),
    timestamp VARCHAR(100),
    request VARCHAR(100),
    resource VARCHAR(255),
    http_code INT,
    size INT,
    agent VARCHAR(255),
    is_bot BOOLEAN
);