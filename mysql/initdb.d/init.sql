DROP DATABASE IF EXISTS baseball-score;
CREATE DATABASE baseball-score;
USE baseball-score;
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