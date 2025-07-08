import mongoose, { type Document, Schema } from "mongoose"
import bcrypt from "bcryptjs"

export interface IUser extends Document {
  name: string
  email: string
  password?: string
  dateOfBirth?: Date
  avatar?: string
  googleId?: string
  firebaseUid?: string
  authProvider: "email" | "google" | "firebase"
  isEmailVerified: boolean
  otp?: string
  otpExpires?: Date
  createdAt: Date
  updatedAt: Date
  comparePassword(candidatePassword: string): Promise<boolean>
}

const userSchema = new Schema<IUser>(
  {
    name: {
      type: String,
      required: true,
      trim: true,
      minlength: 2,
      maxlength: 50,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },
    password: {
      type: String,
      minlength: 6,
    },
    dateOfBirth: {
      type: Date,
    },
    avatar: {
      type: String,
    },
    googleId: {
      type: String,
      sparse: true,
    },
    firebaseUid: {
      type: String,
      sparse: true,
    },
    authProvider: {
      type: String,
      enum: ["email", "google", "firebase"],
      default: "email",
    },
    isEmailVerified: {
      type: Boolean,
      default: false,
    },
    otp: {
      type: String,
    },
    otpExpires: {
      type: Date,
    },
  },
  {
    timestamps: true,
  },
)

// Hash password before saving
userSchema.pre("save", async function (next) {
  if (!this.isModified("password") || !this.password) return next()

  try {
    const salt = await bcrypt.genSalt(12)
    this.password = await bcrypt.hash(this.password, salt)
    next()
  } catch (error: any) {
    next(error)
  }
})

// Compare password method
userSchema.methods.comparePassword = async function (candidatePassword: string): Promise<boolean> {
  if (!this.password) return false
  return bcrypt.compare(candidatePassword, this.password)
}

export default mongoose.model<IUser>("User", userSchema)
