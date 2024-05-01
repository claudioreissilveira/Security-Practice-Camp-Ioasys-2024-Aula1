// seeders/demo-users.js
const { QueryTypes } = require('sequelize');
const sequelize = require('../sequelize');

module.exports = {
  up: async () => {
    // Adiciona 10 usuários de exemplo
    for (let i = 0; i < 10; i++) {
      await sequelize.query(`INSERT INTO users (username, password, "createdAt", "updatedAt") VALUES ('user${i}', 'password${i}', NOW(), NOW())`, { type: QueryTypes.INSERT });
    }
  },
  down: async () => {
    // Remove todos os usuários adicionados
    await sequelize.query("DELETE FROM users", { type: QueryTypes.DELETE });
  },
};
