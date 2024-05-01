const Sequelize = require('sequelize');
const sequelize = require('../sequelize');
const bcrypt = require('bcrypt');

const User = sequelize.define('user', { // O metodo anterior armazenava a senha dos usuarios em texto simples, isso e um pratica insegura porque expoe os dados dos usuarios a qualquer um que acesso o BD. A boa pratica se utiliza o hash e salt para aumentar a seguranca da contra ataques maliciosos.
  username: Sequelize.STRING,
  passwordHash: Sequelize.STRING,
  salt: Sequelize.STRING
}, {
  hooks: {
    beforeCreate: async (user) => {
      const salt = await bcrypt.genSalt(10);
      user.salt = salt;
      user.passwordHash = await bcrypt.hash(user.password, salt);
    }
  }
});

module.exports = User;
