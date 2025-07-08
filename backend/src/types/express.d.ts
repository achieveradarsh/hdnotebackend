import type { IUser } from "../models/User"

declare global {
  namespace Express {
    interface User extends IUser {}
  }
}
