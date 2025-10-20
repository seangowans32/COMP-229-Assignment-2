import jwt from "jsonwebtoken";
import User from "../models/user.model.js";
import config from "../../config/config.js";

// REGISTER new user
export const register = async (req, res) => {
  try {
    const user = new User(req.body);
    await user.save();
    res.status(201).json({ message: "Signup successful!", user });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
};

// LOGIN existing user
export const login = async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email });
    if (!user || !user.comparePassword(req.body.password)) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    // Create JWT token
    const token = jwt.sign({ _id: user._id }, config.jwtSecret, { expiresIn: "1h" });

    // Set cookie with proper options
    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 3600000 // 1 hour in milliseconds
    };
    
    res.cookie("t", token, cookieOptions);
    res.json({ token, user: { _id: user._id, name: user.name, email: user.email } });
  } catch (err) {
    res.status(400).json({ error: "Could not sign in" });
  }
};

// LOGOUT
export const logout = (req, res) => {
  // Clear cookie with same options used when setting it
  const cookieOptions = {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  };
  
  res.clearCookie("t", cookieOptions);
  res.json({ message: "Signed out successfully" });
};

// MIDDLEWARE: verify JWT for protected routes
export const requireSignin = (req, res, next) => {
  try {
    // Try to get token from Authorization header first
    let token = req.headers.authorization?.split(" ")[1];
    
    // If no token in header, try to get from cookie
    if (!token) {
      token = req.cookies.t;
    }
    
    if (!token) {
      return res.status(401).json({ error: "No token provided" });
    }

    const decoded = jwt.verify(token, config.jwtSecret);
    req.auth = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
};