import express from "express"
import Note from "../models/Note"
import { authenticate } from "../middleware/auth"
import { createNoteSchema, updateNoteSchema } from "../validation/note"

const router = express.Router()

// Get all notes for authenticated user
router.get("/", authenticate, async (req, res) => {
  try {
    const userId = (req.user as any)._id
    const notes = await Note.find({ userId }).sort({ isPinned: -1, updatedAt: -1 })

    res.json({
      message: "Notes retrieved successfully",
      notes,
    })
  } catch (error: any) {
    console.error("Get notes error:", error)
    res.status(500).json({ message: "Internal server error" })
  }
})

// Create new note
router.post("/", authenticate, async (req, res) => {
  try {
    const { error, value } = createNoteSchema.validate(req.body)
    if (error) {
      return res.status(400).json({ message: error.details[0].message })
    }

    const userId = (req.user as any)._id
    const note = await Note.create({
      ...value,
      userId,
    })

    res.status(201).json({
      message: "Note created successfully",
      note,
    })
  } catch (error: any) {
    console.error("Create note error:", error)
    res.status(500).json({ message: "Internal server error" })
  }
})

// Get single note
router.get("/:id", authenticate, async (req, res) => {
  try {
    const userId = (req.user as any)._id
    const note = await Note.findOne({
      _id: req.params.id,
      userId,
    })

    if (!note) {
      return res.status(404).json({ message: "Note not found" })
    }

    res.json({
      message: "Note retrieved successfully",
      note,
    })
  } catch (error: any) {
    console.error("Get note error:", error)
    res.status(500).json({ message: "Internal server error" })
  }
})

// Update note
router.put("/:id", authenticate, async (req, res) => {
  try {
    const { error, value } = updateNoteSchema.validate(req.body)
    if (error) {
      return res.status(400).json({ message: error.details[0].message })
    }

    const userId = (req.user as any)._id
    const note = await Note.findOneAndUpdate({ _id: req.params.id, userId }, value, {
      new: true,
      runValidators: true,
    })

    if (!note) {
      return res.status(404).json({ message: "Note not found" })
    }

    res.json({
      message: "Note updated successfully",
      note,
    })
  } catch (error: any) {
    console.error("Update note error:", error)
    res.status(500).json({ message: "Internal server error" })
  }
})

// Delete note
router.delete("/:id", authenticate, async (req, res) => {
  try {
    const userId = (req.user as any)._id
    const note = await Note.findOneAndDelete({
      _id: req.params.id,
      userId,
    })

    if (!note) {
      return res.status(404).json({ message: "Note not found" })
    }

    res.json({
      message: "Note deleted successfully",
    })
  } catch (error: any) {
    console.error("Delete note error:", error)
    res.status(500).json({ message: "Internal server error" })
  }
})

// Search notes
router.get("/search/:query", authenticate, async (req, res) => {
  try {
    const { query } = req.params
    const userId = (req.user as any)._id

    const notes = await Note.find({
      userId,
      $or: [
        { title: { $regex: query, $options: "i" } },
        { content: { $regex: query, $options: "i" } },
        { tags: { $in: [new RegExp(query, "i")] } },
      ],
    }).sort({ isPinned: -1, updatedAt: -1 })

    res.json({
      message: "Search completed successfully",
      notes,
      query,
    })
  } catch (error: any) {
    console.error("Search notes error:", error)
    res.status(500).json({ message: "Internal server error" })
  }
})

export default router
