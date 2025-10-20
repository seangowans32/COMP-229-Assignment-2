import express from "express";
import { register, login, logout, requireSignin } from "../controllers/auth.controller.js";

const router = express.Router();

router.post("/register", register);
router.post("/login", login);
router.get("/logout", logout);

// Example protected route
router.get("/secret", requireSignin, (req, res) => {
  res.json({ message: "Access granted! You reached a protected route." });
});

export default router;