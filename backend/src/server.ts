import dotenv from "dotenv"
import path from "path"

// Load environment variables FIRST - with explicit path
dotenv.config({ path: path.join(__dirname, "../.env") })

// Debug environment loading
console.log("🔍 Environment Loading Debug:")
console.log("Current directory:", __dirname)
console.log("Looking for .env at:", path.join(__dirname, "../.env"))
console.log("EMAIL_USER loaded:", process.env.EMAIL_USER || "NOT LOADED")
console.log("EMAIL_PASS loaded:", process.env.EMAIL_PASS ? "LOADED" : "NOT LOADED")

import express from "express"
import cors from "cors"
import helmet from "helmet"
import rateLimit from "express-rate-limit"
import session from "express-session"
import passport from "passport"
import { connectDB } from "./config/database"
import { setupPassport } from "./config/passport"
import authRoutes from "./routes/auth"
import noteRoutes from "./routes/notes"
import userRoutes from "./routes/user"
import { errorHandler } from "./middleware/errorHandler"

const app = express()
const PORT = process.env.PORT || 5000

// Connect to MongoDB
connectDB()

// Setup Passport
setupPassport()

// Security middleware
app.use(helmet())
app.use(
  cors({
    origin: process.env.FRONTEND_URL || "http://localhost:3000",
    credentials: true,
  }),
)

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
})
app.use(limiter)

// Body parsing middleware
app.use(express.json({ limit: "10mb" }))
app.use(express.urlencoded({ extended: true }))

// Session middleware
app.use(
  session({
    secret: process.env.SESSION_SECRET || "fallback-secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === "production",
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
    },
  }),
)

// Passport middleware
app.use(passport.initialize())
app.use(passport.session())

// Routes
app.use("/api/auth", authRoutes)
app.use("/api/notes", noteRoutes)
app.use("/api/user", userRoutes)

// Health check
app.get("/api/health", (req, res) => {
  res.json({ status: "OK", message: "HD Notes API is running" })
})

// Error handling middleware
app.use(errorHandler)

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`)
  console.log(`📱 Frontend URL: ${process.env.FRONTEND_URL}`)
})

export default app
