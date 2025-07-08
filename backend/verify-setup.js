// Quick verification script
const fs = require("fs")
const path = require("path")

console.log("🔍 Verifying HD Notes Backend Setup...\n")

// Check if .env file exists
const envPath = path.join(__dirname, ".env")
if (fs.existsSync(envPath)) {
  console.log("✅ .env file found")
  const envContent = fs.readFileSync(envPath, "utf8")
  if (envContent.includes("MONGODB_URI") && envContent.includes("JWT_SECRET")) {
    console.log("✅ Environment variables configured")
  } else {
    console.log("❌ Environment variables missing")
  }
} else {
  console.log("❌ .env file not found")
}

// Check if node_modules exists
if (fs.existsSync(path.join(__dirname, "node_modules"))) {
  console.log("✅ Dependencies installed")
} else {
  console.log("❌ Dependencies not installed - run npm install")
}

// Check TypeScript compilation
const { execSync } = require("child_process")
try {
  execSync("npx tsc --noEmit", { stdio: "pipe" })
  console.log("✅ TypeScript compilation successful")
} catch (error) {
  console.log("❌ TypeScript compilation failed")
  console.log(error.stdout?.toString() || error.message)
}

console.log("\n🚀 Setup verification complete!")
