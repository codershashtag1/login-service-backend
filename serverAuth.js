require("dotenv").config();

const express = require("express");
const app = express();
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

app.use(express.json());

let refreshTokenArr = [];
let usersArr = [];

app.post("/createUser", async (req, res) => {
  try {
    console.log(req.body.userName);
    console.log(req.body.password);
    let salt = await bcrypt.genSalt(10);
    let hashpassword = await bcrypt.hash(req.body.password, salt);
    let userData = { userName: req.body.userName, password: hashpassword };
    usersArr.push(userData);
    res.status(201).send();
  } catch (err) {
    console.log(err);
    res.status(500).send();
  }
});

app.post("/token", (req, res) => {
  let token = req.body.token;
  if (token == null) res.sendStatus(401);
  if (!refreshTokenArr.includes(token)) res.sendStatus(403);
  jwt.verify(token, process.env.REFRESH_TOKEN_KEY, (err, user) => {
    if (err) res.sendStatus(403);
    let accessToken = generateAccessToken({ userName: user.userName });
    res.json({ accessToken: accessToken });
  });
});

app.post("/login", async (req, res) => {
  try {
    // Authenticate User
    let userName = req.body.userName;
    let password = req.body.password;

    let filterUser = usersArr.find((e) => e.userName == userName);
    if (filterUser == null) {
      res.sendStatus(400).send("User not found");
    }
    console.log(filterUser.password);
    console.log(await bcrypt.compare(password, filterUser.password));
    if (await bcrypt.compare(password, filterUser.password)) {
      let userObj = { userName: userName };
      let accessToken = generateAccessToken(userObj);
      let refreshToken = jwt.sign(userObj, process.env.REFRESH_TOKEN_KEY);
      refreshTokenArr.push(refreshToken);

      res.json({ accessToken: accessToken, refreshToken: refreshToken });
    } else {
      res.send("Not Allowed");
    }
  } catch (err) {
    res.sendStatus(500);
  }
});

function generateAccessToken(user) {
  return jwt.sign(user, process.env.ACCESS_TOKEN_KEY, { expiresIn: "60s" });
}

app.listen(4000);
