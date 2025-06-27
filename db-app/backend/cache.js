const Memcached = require('memcached');
const memcached = new Memcached('memcached:11211');

module.exports = memcached;
