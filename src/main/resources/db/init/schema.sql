CREATE TABLE account
(
    id       BIGINT NOT NULL,
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    CONSTRAINT pk_account PRIMARY KEY (id)
);
