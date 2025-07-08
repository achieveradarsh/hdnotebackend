const jwt = require("jsonwebtoken")

export const generateToken = (userId: string): string => {
  const secret = process.env.JWT_SECRET || "fallback-secret"
  return jwt.sign({ userId }, secret, { expiresIn: "10m" })
}

export const generateOTP = (): string => {
  return Math.floor(100000 + Math.random() * 900000).toString()
}
