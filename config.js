const sequelize = require('./sequelize');

module.exports = {
  development: {
    ...sequelize.config,
    dialect: 'postgres'
  },
}