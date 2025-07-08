import express from "express"
import { authenticate } from "../middleware/auth"
import User from "../models/User"

const router = express.Router()

// Get user profile
router.get("/profile", authenticate, async (req, res) => {
  try {
    const userId = (req.user as any)._id
    const user = await User.findById(userId).select("-password -otp -otpExpires")

    res.json({
      message: "Profile retrieved successfully",
      user,
    })
  } catch (error: any) {
    console.error("Get profile error:", error)
    res.status(500).json({ message: "Internal server error" })
  }
})

// Update user profile
router.put("/profile", authenticate, async (req, res) => {
  try {
    const { name, dateOfBirth } = req.body
    const userId = (req.user as any)._id

    const user = await User.findByIdAndUpdate(userId, { name, dateOfBirth }, { new: true, runValidators: true }).select(
      "-password -otp -otpExpires",
    )

    res.json({
      message: "Profile updated successfully",
      user,
    })
  } catch (error: any) {
    console.error("Update profile error:", error)
    res.status(500).json({ message: "Internal server error" })
  }
})

export default router
