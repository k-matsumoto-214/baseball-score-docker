DROP DATABASE IF EXISTS baseball_score;
CREATE DATABASE baseball_score;
USE baseball_score;
DROP TABLE IF EXISTS test;

CREATE TABLE test
(
  id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  name TEXT NOT NULL
)DEFAULT CHARACTER
  SET=utf8;

  INSERT INTO test
    (name)
  VALUES
    ("田中"),
    ("鈴木"),
    ("ああああああ");