require('dotenv/config');
// sequelize.js
const Sequelize = require('sequelize');

const sequelize = new Sequelize(process.env.DB_NAME, process.env.DB_USER, process.env.DB_PASS, {
  dialect: 'postgres',
  port: 5432
});

module.exports = sequelize;
