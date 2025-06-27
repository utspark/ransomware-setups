const { Pool } = require('pg');

const pool = new Pool({
	  host: 'db',
	  port: 5432,
	  user: 'postgres',
	  password: 'postgres',
	  database: 'app_db',
});

module.exports = pool;
