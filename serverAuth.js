require("dotenv").config();

const express = require("express");
const app = express();
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const cookieParser = require("cookie-parser");
// const cors = require("cors");


// app.use(
//   cors({
//     origin: "http://localhost:3000", // Allow requests from the authorization server
//     credentials: true, // Allow cookies to be sent
//   })
// );
app.use(cookieParser());
app.use(express.json());

let refreshTokenArr = [];
let usersArr = [];

app.post("/createUser", async (req, res) => {
  try {
    console.log(req.body.password);
    let salt = await bcrypt.genSalt(10);
    let hashpassword = await bcrypt.hash(req.body.password, salt);
    let userfound = usersArr.find((e) => e.userName == req.body.userName);
    if(userfound) {
      res.status(201).send("User Already Exists");
    }
    let userData = { userName: req.body.userName, password: hashpassword };
    usersArr.push(userData);
    res.send('User Created SuccessFully');
  } catch (err) {
    console.log(err);
    res.status(500).send();
  }
});

app.delete('/logoutJWTStoreInCookies', (req, res) => {
  let refreshToken = req.cookies.refreshToken;
  if(!refreshToken) res.sendStatus(401);

  res.cookie('accessToken', '', {
    httpOnly: true,
    sameSite: 'Strict',
    secure: false,
    maxAge: 0
  })

  res.cookie("refreshToken", "", {
    httpOnly: true,
    sameSite: "Strict",
    secure: false,
    maxAge: 0,
  });

  res.send('User Logout Successfylly');

})

app.post("/token", (req, res) => {
  let refreshToken = req.body.token;
  if (refreshToken == null) res.sendStatus(401);
  if (!refreshTokenArr.includes(refreshToken)) res.sendStatus(403);
  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_KEY, (err, user) => {
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


app.post("/tokenJWTStoreInCookie", (req, res) => {
  let refreshToken = req.cookies.refreshToken;
  if (refreshToken == null) res.sendStatus(401);
  if (!refreshTokenArr.includes(refreshToken)) res.sendStatus(403);
  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_KEY, (err, user) => {
    if (err) res.send('Please login again');
    let accessToken = generateAccessToken({ userName: user.userName });
    res.cookie("accessToken", accessToken, {
      httpOnly: true,
      sameSite: "strict",
      secure: false,
      maxAge: 90000,
    });
    res.send('Token Generated');
  });
});

app.post("/loginJwtStoreInCookie", async (req, res) => {
  try {
    // Authenticate User
    let userName = req.body.userName;
    let password = req.body.password;

    let filterUser = usersArr.find((e) => e.userName == userName);
    if (filterUser == null) {
      res.sendStatus(400).send("User not found");
    }

    if (await bcrypt.compare(password, filterUser.password)) {
      let userObj = { userName: userName };
      let accessToken = generateAccessToken(userObj);
      let refreshToken = jwt.sign(userObj, process.env.REFRESH_TOKEN_KEY);
      refreshTokenArr.push(refreshToken);
      res.cookie("accessToken", accessToken, {
        httpOnly: true,
        sameSite: "strict",
        secure: false,
        maxAge: 90000,
      });
      res.cookie("refreshToken", refreshToken, {
        httpOnly: true,
        sameSite: "strict",
        secure: false,
        maxAge: 90000,
      });
      res.send("Login Successfully");
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
