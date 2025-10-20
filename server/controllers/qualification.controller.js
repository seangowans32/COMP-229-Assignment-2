import Qualification from "../models/qualification.model.js";

// CREATE a new qualification
export const createQualification = async (req, res) => {
  try {
    const qualification = await Qualification.create(req.body);
    res.status(201).json(qualification);
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
};

// READ all qualifications
export const getAllQualifications = async (req, res) => {
  try {
    const qualifications = await Qualification.find();
    res.status(200).json(qualifications);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// READ one qualification by ID
export const getQualificationById = async (req, res) => {
  try {
    const qualification = await Qualification.findById(req.params.id);
    if (!qualification) return res.status(404).json({ message: "Qualification not found" });
    res.json(qualification);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// UPDATE a qualification by ID
export const updateQualification = async (req, res) => {
  try {
    const updated = await Qualification.findByIdAndUpdate(req.params.id, req.body, { new: true });
    res.json(updated);
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
};

// DELETE a qualification by ID
export const deleteQualification = async (req, res) => {
  try {
    await Qualification.findByIdAndDelete(req.params.id);
    res.json({ message: "Qualification deleted successfully" });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// DELETE all qualifications
export const deleteAllQualifications = async (req, res) => {
  try {
    await Qualification.deleteMany();
    res.json({ message: "All qualifications deleted successfully" });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};