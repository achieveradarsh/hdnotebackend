// Test environment loading
require("dotenv").config()

console.log("🧪 Testing Environment Variables:")
console.log("EMAIL_USER:", process.env.EMAIL_USER)
console.log("EMAIL_PASS:", process.env.EMAIL_PASS ? "SET" : "NOT SET")
console.log("MONGODB_URI:", process.env.MONGODB_URI ? "SET" : "NOT SET")

if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
  console.log("✅ Environment variables loaded successfully!")
} else {
  console.log("❌ Environment variables not loaded")
  console.log("📁 Make sure .env file exists in backend folder")
}
