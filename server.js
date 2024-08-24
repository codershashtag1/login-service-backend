require("dotenv").config();

const express = require("express");
const app = express();
const jwt = require("jsonwebtoken");

app.use(express.json());

const userPost = [
  {
    userId: 1,
    userName: "Darshana",
    post: "Post 1",
  },
  {
    userId: 2,
    userName: "Naveen",
    post: "Post 2",
  },
];

app.get("/posts", authenticateToken, (req, res) => {
  res.json(userPost.filter((e) => e.userName == req.user.userName));
});

app.listen(3000);

function authenticateToken(req, res, next) {
  let header = req.headers["authorization"];
  let token = header && header.split(" ")[1];
  if (token == null) res.sendStatus(401);
  jwt.verify(token, process.env.ACCESS_TOKEN_KEY, (err, user) => {
    if (err) res.sendStatus(403);
    req.user = user;
    next();
  });
}
