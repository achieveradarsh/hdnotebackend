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

// CORS Configuration - FIXED for production
const allowedOrigins = [
  "http://localhost:3000",
  "https://localhost:3000",
  process.env.FRONTEND_URL,
  "https://hd-notes-notetakingapp10.vercel.app", // Add your actual Vercel URL here
  "https://*.vercel.app", // Allow all Vercel subdomains
]

app.use(
  cors({
    origin: (origin, callback) => {
      // Allow requests with no origin (mobile apps, curl, etc.)
      if (!origin) return callback(null, true)

      // Check if origin is in allowed list or matches Vercel pattern
      if (
        allowedOrigins.some(
          (allowed) => allowed === origin || (allowed && origin.includes("vercel.app")) || origin.includes("localhost"),
        )
      ) {
        return callback(null, true)
      }

      console.log("CORS blocked origin:", origin)
      callback(new Error("Not allowed by CORS"))
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"],
  }),
)

// Handle preflight requests
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
    cors: process.env.FRONTEND_URL,
    timestamp: new Date().toISOString(),
  })
})

// Root route for testing
app.get("/", (req: any, res: any) => {
  res.json({
    message: "HD Notes Backend API",
    health: "/api/health",
    frontend: process.env.FRONTEND_URL,
  })
})

// Error handling middleware
app.use(errorHandler)

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`)
  console.log(`📱 Frontend URL: ${process.env.FRONTEND_URL}`)
  console.log(`🌍 CORS enabled for: ${allowedOrigins.join(", ")}`)
})

export default app
