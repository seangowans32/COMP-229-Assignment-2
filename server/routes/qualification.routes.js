import express from "express";
import {
  createQualification,
  getAllQualifications,
  getQualificationById,
  updateQualification,
  deleteQualification,
  deleteAllQualifications
} from "../controllers/qualification.controller.js";

const router = express.Router();

// Define routes
router.post("/", createQualification);
router.get("/", getAllQualifications);
router.get("/:id", getQualificationById);
router.put("/:id", updateQualification);
router.delete("/:id", deleteQualification);
router.delete("/", deleteAllQualifications);

export default router;