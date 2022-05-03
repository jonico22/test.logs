/*
    0- Node profiling 
    $ node --prof server.js

    1- Creamos el usuario para probar los metodos auth
    $ curl -X GET "http://localhost:8080/newUser?username=marian&password=qwerty123"

    2- Prueba artillery modo bloqueante
    $ artillery quick --count 10 -n 50 "http://localhost:8080/auth-bloq?username=marian&password=qwerty123" > result_bloq.txt

    **Detenemos y renombramos el "insolate-v8.log"

    3- Creamos el usuario para probar los metodos auth
    $ curl -X GET "http://localhost:8080/newUser?username=marian&password=qwerty123"

    4- Prueba artillery modo bloqueante
    $ artillery quick --count 10 -n 50 "http://localhost:8080/auth-nobloq?username=marian&password=qwerty123" > result_nobloq.txt

    5- Comparamos el rendimiento/profiling de cada uno, primero decodificamos los v8.log
    $ node --prof-process bloq-v8.log > result_prof-bloq.txt
    $ node --prof-process nobloq-v8.log > result_prof-nobloq.txt

    Node inspect
    0- Node inspect 
    $ node --inspect server.js

*/

const express = require("express");
const crypto = require("crypto");

const app = express();

const users = {}

app.use(express.static('public'))

app.get("/getUsers", (req, res) => {
  res.json({ users })
})

app.get("/newUser", (req, res) => {
  let username = req.query.username || "";
  const password = req.query.password || "";

  username = username.replace(/[!@#$%^&*]/g, "");

  if (!username || !password || users[ username ]) {
    return res.sendStatus(400);
  }

  const salt = crypto.randomBytes(128).toString("base64");
  const hash = crypto.pbkdf2Sync(password, salt, 10000, 512, "sha512");

  users[ username ] = { salt, hash };

  res.sendStatus(200);
});

app.get("/auth-bloq", (req, res) => {
  let username = req.query.username || "";
  const password = req.query.password || "";

  username = username.replace(/[!@#$%^&*]/g, "");

  if (!username || !password || !users[ username ]) {
    // process.exit(1)
    return res.sendStatus(400);
  }

  const { salt, hash } = users[ username ];
  const encryptHash = crypto.pbkdf2Sync(password, salt, 10000, 512, "sha512");

  if (crypto.timingSafeEqual(hash, encryptHash)) {
    res.sendStatus(200);
  } else {
    // process.exit(1)
    res.sendStatus(401);
  }
});


app.get("/auth-nobloq", (req, res) => {
  let username = req.query.username || "";
  const password = req.query.password || "";

  username = username.replace(/[!@#$%^&*]/g, "");

  if (!username || !password || !users[ username ]) {
    // process.exit(1)
    return res.sendStatus(400);
  }

  crypto.pbkdf2(password, users[ username ].salt, 10000, 512, 'sha512', (err, hash) => {
    if (users[ username ].hash.toString() === hash.toString()) {
      res.sendStatus(200);
    } else {
      // process.exit(1)
      res.sendStatus(401);
    }
  });
});

const PORT = parseInt(process.argv[ 2 ]) || 8080;
const server = app.listen(PORT, () => {
  console.log(`Servidor escuchando en el puerto ${PORT}`);
});
server.on("error", (error) => console.log(`Error en servidor: ${error}`));
