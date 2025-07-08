import mongoose, { type Document, Schema } from "mongoose"

export interface INote extends Document {
  title: string
  content: string
  userId: mongoose.Types.ObjectId
  tags: string[]
  isPinned: boolean
  createdAt: Date
  updatedAt: Date
}

const noteSchema = new Schema<INote>(
  {
    title: {
      type: String,
      required: true,
      trim: true,
      maxlength: 200,
    },
    content: {
      type: String,
      default: "",
      maxlength: 10000,
    },
    userId: {
      type: Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    tags: [
      {
        type: String,
        trim: true,
        maxlength: 30,
      },
    ],
    isPinned: {
      type: Boolean,
      default: false,
    },
  },
  {
    timestamps: true,
  },
)

// Index for better query performance
noteSchema.index({ userId: 1, createdAt: -1 })
noteSchema.index({ userId: 1, title: "text", content: "text" })

export default mongoose.model<INote>("Note", noteSchema)
