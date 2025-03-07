const express = require("express");
require("dotenv").config();
const bcrypt = require("bcrypt");
const UUID = require("./models/uuid.model.js");
const { initialiseDatabase } = require("./db/db.connect.js");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
initialiseDatabase();

const corsOptions = {
  origin: "*",
  credentials: true,
  optionSuccessStatus: 200,
};

app.use(cors(corsOptions));

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

app.listen(3000, () => console.log("Server is running on 3000"));
