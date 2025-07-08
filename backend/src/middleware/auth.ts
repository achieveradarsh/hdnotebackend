import type { Request, Response, NextFunction } from "express"
import jwt from "jsonwebtoken"
import User, { type IUser } from "../models/User"

export const authenticate = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const token = req.header("Authorization")?.replace("Bearer ", "")

    if (!token) {
      res.status(401).json({
        message: "Access denied. No token provided.",
        code: "NO_TOKEN",
      })
      return
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET as string) as { userId: string }
    const user = (await User.findById(decoded.userId).select("-password")) as IUser

    if (!user) {
      res.status(401).json({
        message: "Invalid token.",
        code: "INVALID_TOKEN",
      })
      return
    }

    req.user = user
    next()
  } catch (error: any) {
    if (error.name === "TokenExpiredError") {
      res.status(401).json({
        message: "Token expired. Please login again.",
        code: "TOKEN_EXPIRED",
      })
      return
    }

    res.status(401).json({
      message: "Invalid token.",
      code: "INVALID_TOKEN",
    })
  }
}
