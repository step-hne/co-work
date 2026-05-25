<?php

declare(strict_types=1);

include_once dirname(__DIR__) . '/env.php';
load_env_file(__DIR__ . '/.env');

class dbObj
{
	public $servername;
	public $username;
	public $password;
	public $dbname;
	public $conn;

	public function __construct()
	{
		$this->servername = app_env('DB_HOST', 'localhost');
		$this->username = app_required_env('DB_USER');
		$this->password = app_required_env('DB_PASSWORD');
		$this->dbname = app_required_env('DB_NAME');
	}

	public function getConnstring()
	{
		$con = mysqli_connect($this->servername, $this->username, $this->password, $this->dbname);

		if ($con === false) {
			throw new RuntimeException('Database connection failed.');
		}

		mysqli_set_charset($con, 'utf8mb4');
		$this->conn = $con;

		return $this->conn;
	}

	public function closeConn(): void
	{
		if ($this->conn instanceof mysqli) {
			@mysqli_close($this->conn);
			$this->conn = null;
		}
	}

	public function __destruct()
	{
		$this->closeConn();
	}
}