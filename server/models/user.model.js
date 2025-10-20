import mongoose from "mongoose";
import bcrypt from "bcryptjs";

const userSchema = new mongoose.Schema({
  name: { type: String, trim: true, required: "Name is required" },
  email: { type: String, trim: true, unique: "Email already exists", required: "Email is required" },
  password: { type: String, required: "Password is required" },
  created: { type: Date, default: Date.now },
  updated: Date
});

// Hash password before saving
userSchema.pre("save", function (next) {
  if (!this.isModified("password")) return next();
  this.password = bcrypt.hashSync(this.password, 10);
  next();
});

// Compare passwords during login
userSchema.methods.comparePassword = function (password) {
  return bcrypt.compareSync(password, this.password);
};

export default mongoose.model("User", userSchema);