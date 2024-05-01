// index.js
const express = require("express");
const bodyParser = require("body-parser");
const User = require("./models/User");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(bodyParser.json());

// Endpoint de login (vulnerável a SQL Injection)
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = hash(password); //O metodo anterior estava diretamente inserindo na consulta SQL sem qualquer validação adequada. Isso permite que injete código SQL malicioso na tentativa de login e comprometa a segurança do sistema, para isso utilizamos o algoritmo hash para proteger as senhas armazenadas.
  const user = await User.findOne({
    where: { username: username, password: hashedPassword },
  });

  if (user) {
    res.json({ message: "Login successful", user });
  } else {
    res.status(401).json({ message: "Invalid credentials" });
  }
});

// Endpoint de listagem de usuários (expondo dados sensíveis)
app.get("/users", async (req, res) => {
  const users = await User.findAll({
    attributes: ["id", "username"], // O metodo anterior estava expondo de maneira direta a senha, isso permite que qualquer pessoa que acesse esse endpoint tenha acessos aos dados em texto simples.
  });
  res.json(users);
});

// Endpoint de detalhe do usuário logado (expondo senha)
app.get("/profile", async (req, res) => {
  const { username } = req.query;
  const user = await User.findOne({ where: { username: username ?? null } });
  if (user) { //O metodo anterior exibia a senha do usuário através da resposta quando o endpoint /profile é acessado com um nome de usuário específico. Pode ser perigoso, já que expõe informações confidenciais a qualquer um que acesse o endpoint. Sendo assim a exclusao do campo de senha, garante que a senha do usuário não seja incluída na resposta.
    const { password, ...userDataWithoutPassword } = user.toJSON();
    res.json(userDataWithoutPassword);
  } else {
    res.status(404).json({ message: "User not found" });
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
