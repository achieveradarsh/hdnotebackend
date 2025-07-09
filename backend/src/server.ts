import dotenv from "dotenv"
import path from "path"

// Load environment variables FIRST
dotenv.config({ path: path.join(__dirname, "../.env") })

import express from "express"
import cors from "cors"
import helmet from "helmet"
import rateLimit from "express-rate-limit"
import session from "express-session"
import { connectDB } from "./config/database"
import authRoutes from "./routes/auth"
import noteRoutes from "./routes/notes"
import userRoutes from "./routes/user"
import { errorHandler } from "./middleware/errorHandler"

const app = express()
const PORT = process.env.PORT || 5000

// Connect to MongoDB
connectDB()

// CORS Configuration - FIXED for your specific Vercel domain
const allowedOrigins = [
  "http://localhost:3000",
  "https://hdnotes.adarshvault.me",
  "https://v0-notetakingapp10.vercel.app", // YOUR EXACT VERCEL DOMAIN
  "https://hdnotes-notetakingapp10.vercel.app", // Alternative domain
  process.env.FRONTEND_URL,
]

app.use(
  cors({
    origin: (origin, callback) => {
      console.log("🔍 CORS Check - Origin:", origin)

      // Allow requests with no origin (mobile apps, curl, etc.)
      if (!origin) return callback(null, true)

      // Check if origin is in allowed list or is a Vercel domain
      if (allowedOrigins.includes(origin) || origin.includes("vercel.app") || origin.includes("localhost")) {
        console.log("✅ CORS ALLOWED for:", origin)
        return callback(null, true)
      }

      console.log("❌ CORS BLOCKED for:", origin)
      callback(new Error("Not allowed by CORS"))
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"],
  }),
)

// Handle preflight requests explicitly
app.options("*", cors())

// Security middleware
app.use(
  helmet({
    crossOriginEmbedderPolicy: false,
    contentSecurityPolicy: false,
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

// Debug middleware to log requests
app.use((req, res, next) => {
  console.log(`${req.method} ${req.path} - Origin: ${req.get("Origin")}`)
  next()
})

// Routes
app.use("/api/auth", authRoutes)
app.use("/api/notes", noteRoutes)
app.use("/api/user", userRoutes)

// Health check
app.get("/api/health", (req: any, res: any) => {
  res.json({
    status: "OK",
    message: "HD Notes API is running",
    allowedOrigins: allowedOrigins,
    timestamp: new Date().toISOString(),
  })
})

// Root route for testing
app.get("/", (req: any, res: any) => {
  res.json({
    message: "HD Notes Backend API",
    health: "/api/health",
    allowedOrigins: allowedOrigins,
  })
})

// Error handling middleware
app.use(errorHandler)

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`)
  console.log(`📱 Allowed Origins: ${allowedOrigins.join(", ")}`)
  console.log(`🌍 CORS enabled for Vercel domains`)
})

export default app
