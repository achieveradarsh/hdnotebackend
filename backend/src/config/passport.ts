import passport from "passport"
import { Strategy as GoogleStrategy } from "passport-google-oauth20"
import User from "../models/User"

export const setupPassport = () => {
  passport.use(
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID as string,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET as string,
        callbackURL: "/api/auth/google/callback",
      },
      async (accessToken, refreshToken, profile, done) => {
        try {
          // Check if user already exists
          let user = await User.findOne({ googleId: profile.id })

          if (user) {
            return done(null, user)
          }

          // Check if user exists with same email
          user = await User.findOne({ email: profile.emails?.[0]?.value })

          if (user) {
            // Link Google account to existing user
            user.googleId = profile.id
            await user.save()
            return done(null, user)
          }

          // Create new user
          user = await User.create({
            googleId: profile.id,
            name: profile.displayName,
            email: profile.emails?.[0]?.value,
            avatar: profile.photos?.[0]?.value,
            isEmailVerified: true,
            authProvider: "google",
          })

          return done(null, user)
        } catch (error) {
          return done(error, false)
        }
      },
    ),
  )

  passport.serializeUser((user: any, done) => {
    done(null, user._id)
  })

  passport.deserializeUser(async (id: string, done) => {
    try {
      const user = await User.findById(id)
      done(null, user)
    } catch (error) {
      done(error, false)
    }
  })
}
