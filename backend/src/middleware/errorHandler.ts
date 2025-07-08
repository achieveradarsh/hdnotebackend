import type { Request, Response, NextFunction } from "express"

export const errorHandler = (error: any, req: Request, res: Response, next: NextFunction) => {
  console.error("Error:", error)

  // Mongoose validation error
  if (error.name === "ValidationError") {
    const errors = Object.values(error.errors).map((err: any) => err.message)
    return res.status(400).json({
      message: "Validation Error",
      errors,
    })
  }

  // Mongoose duplicate key error
  if (error.code === 11000) {
    const field = Object.keys(error.keyValue)[0]
    return res.status(400).json({
      message: `${field} already exists`,
    })
  }

  // JWT errors
  if (error.name === "JsonWebTokenError") {
    return res.status(401).json({ message: "Invalid token" })
  }

  if (error.name === "TokenExpiredError") {
    return res.status(401).json({ message: "Token expired" })
  }

  // Default error
  res.status(error.statusCode || 500).json({
    message: error.message || "Internal server error",
  })
}
