const express = require('express');
const pool = require('./db');
const memcached = require('./cache');
const tpchQueries = require('./benchmark.js');

//import express from 'express';
//import pool from './db.js';
//import memcached from './cache.js';

const app = express();
const PORT = 3000;

app.get('/data/:id', async (req, res) => {
	const id = parseInt(req.params.id);
	const key = `data:${id}`;

	memcached.get(key, (err, data) => {
		if (data) {
			console.log(`[Cache Hit] Test ${id}`);
			return res.json({ source: 'cache', data: JSON.parse(data) });
		}
		(async () => {
			try {
				const result = await pool.query('SELECT * FROM items WHERE id = $1', [id]);
				memcached.set(key, JSON.stringify(result.rows[0]), 60, () => {});
				console.log(`[Cache Set] ${key}`);
				res.json({ source: 'db', data: result.rows[0] });
			} catch (error) {
				res.status(500).send('Database error');
			}
		})();
	});
});

app.get('/tpch/:id', async (req, res) => {
	const id = parseInt(req.params.id);
	const key = `tpch:${id}`;

	if (!tpchQueries[id]) {
		return res.status(404).json({ error: 'Benchmark query not found' });
	}

	memcached.get(key, (err, data) => {
		if (data) {
			console.log(`[Cache Hit] Benchmark Q${id}`);
			return res.json({ source: 'cache', data: JSON.parse(data) });
		}

		(async () => {
			try {
				const result = await pool.query(tpchQueries[id]);
				memcached.set(key, JSON.stringify(result.rows), 60, (err) => {
					if (err) console.error(`[CACHE SET ERROR] ${key}`, err);
				});
				res.json({ source: 'db', data: result.rows });
			} catch (error) {
				res.status(500).send('Database error');
			}
		})();
	});
});

app.get('/cache/flush', (req, res) => {
	memcached.flush((err) => {
		if (err) return res.status(500).send('Flush failed');
		res.send('Cache cleared');
	});
});

app.listen(PORT, () => console.log(`API server running on port ${PORT}`));
