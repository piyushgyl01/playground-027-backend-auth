const express = require("express");
require("dotenv").config();
const bcrypt = require("bcrypt");
const UUID = require("./models/uuid.model.js");
const { initialiseDatabase } = require("./db/db.connect.js");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const axios = require("axios");
const cookieParser = require("cookie-parser");

const app = express();
initialiseDatabase();
const PORT = process.env.PORT || 4000;

const corsOptions = {
  origin: "http://localhost:3000",
  credentials: true,
  optionSuccessStatus: 200,
};

app.use(cors(corsOptions));
app.use(cookieParser());

app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET;

app.get("/", (req, res) => {
  res.json("HELLO TO AUTH ROXS");
});

app.post("/login", async (req, res) => {
  const { uuid, secretKey } = req.body;

  if (!uuid || !secretKey) {
    return res.status(400).json({ message: "Please provide" });
  }

  try {
    const foundUuid = await UUID.findOne({ uuid });

    if (!foundUuid) {
      return res.status(404).json({ message: "UUID not found" });
    }

    const isSecretKeyCorrect = await bcrypt.compare(
      secretKey,
      foundUuid.secretKey
    );

    if (!isSecretKeyCorrect) {
      return res.status(400).json({ message: "Invalid Credentials" });
    }

    const token = jwt.sign(
      { id: foundUuid._id, uuid: foundUuid.uuid },
      JWT_SECRET,
      {
        expiresIn: "4h",
      }
    );

    res.status(200).json({ message: "Logged in", token, uuid: foundUuid.uuid });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Server error while login.", error: error });
  }
});

app.post("/register", async (req, res) => {
  const { uuid, secretKey } = req.body;

  if (!uuid || !secretKey) {
    return res
      .status(400)
      .json({ message: "Please provide UUID and secretKey" });
  }

  try {
    const existingUuid = await UUID.findOne({ uuid });

    if (existingUuid) {
      return res.status(409).json({ message: "UUID already registered" });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedSecretKey = await bcrypt.hash(secretKey, salt);

    const newUuid = new UUID({
      uuid: uuid,
      secretKey: hashedSecretKey,
    });

    await newUuid.save();

    const token = jwt.sign(
      { id: newUuid._id, uuid: newUuid.uuid },
      JWT_SECRET,
      {
        expiresIn: "4h",
      }
    );

    res.status(201).json({
      message: "UUID registered successfully",
      token,
      uuid: newUuid.uuid,
    });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({ message: "Server Error", error: error.message });
  }
});

const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "No token provided" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ message: "Invalid token" });
  }
};

app.get("/protected", verifyToken, async (req, res) => {
  try {
    const uuid = await UUID.findById(req.user.id);
    if (!uuid) {
      return res.status(404).json({ message: "UUID not found" });
    }
    res.json({
      message: "Protected route accessed successfully",
      uuid: uuid.uuid,
    });
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

app.get("/auth/github", (req, res) => {
  const githubAuthUrl = `https://github.com/login/oauth/authorize?client_id=${process.env.GITHUB_CLIENT_ID}&scope=user,repo,security_events`;

  res.redirect(githubAuthUrl);
});

app.get("/auth/github/callback", async (req, res) => {
  const { code } = req.query;

  if (!code) {
    return res.status(400).send("Authorization code not provided");
  }

  try {
    const tokenResponse = await axios.post(
      "https://github.com/login/oauth/access_token",
      {
        client_id: process.env.GITHUB_CLIENT_ID,
        client_secret: process.env.GITHUB_CLIENT_SECRET,
        code,
      },
      {
        headers: {
          Accept: "application/json",
        },
      }
    );
    const accessToken = tokenResponse.data.access_token;

    res.cookie("access_token", accessToken);
    return res.redirect(`${process.env.FRONTEND_URL}/v1/profile/github`);
  } catch (error) {
    res.status(500).json(error);
  }
});

app.get("/auth/google", (req, res) => {
  const googleAuthUrl = `https://accounts.google.com/o/oauth2/auth?client_id=${process.env.GOOGLE_CLIENT_ID}&redirect_uri=http://localhost:${PORT}/auth/google/callback&response_type=code&scope=profile email`;

  res.redirect(googleAuthUrl);
});

app.get("/auth/google/callback", async (req, res) => {
  const { code } = req.query;

  if (!code) {
    return res.status(400).send("Authorization code not provided");
  }

  try {
    const params = new URLSearchParams();
    params.append("client_id", process.env.GOOGLE_CLIENT_ID);
    params.append("client_secret", process.env.GOOGLE_CLIENT_SECRET);
    params.append("code", code);
    params.append("grant_type", "authorization_code");
    params.append("redirect_uri", `http://localhost:4000/auth/google/callback`);

    const tokenResponse = await axios.post(
      "https://oauth2.googleapis.com/token",
      params.toString(),
      {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
      }
    );

    const accessToken = tokenResponse.data.access_token;

    res.cookie("access_token", accessToken);
    return res.redirect(`${process.env.FRONTEND_URL}/v1/profile/google`);
  } catch (error) {
    console.error("Google OAuth error:", error.response?.data || error.message);
    res.status(500).json({
      error: "Failed to authenticate with Google",
      details: error.response?.data || error.message,
    });
  }
});

app.listen(4000, () => console.log("Server is running on 4000"));
