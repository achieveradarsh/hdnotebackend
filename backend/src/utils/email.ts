import nodemailer from "nodemailer"

// Debug: Log environment variables (remove after testing)
console.log("🔍 Email Debug Info:")
console.log("EMAIL_USER:", process.env.EMAIL_USER)
console.log("EMAIL_PASS:", process.env.EMAIL_PASS ? "***SET***" : "NOT SET")

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER || "satyavalapula@gmail.com",
    pass: process.env.EMAIL_PASS || "vvuwatsfvqnsdyex",
  },
})

// Test connection on startup
transporter.verify((error, success) => {
  if (error) {
    console.log("❌ Email transporter error:", error)
  } else {
    console.log("✅ Email transporter ready")
  }
})

export const sendOTPEmail = async (email: string, otp: string, name: string) => {
  const mailOptions = {
    from: process.env.EMAIL_FROM || "satyavalapula@gmail.com",
    to: email,
    subject: "Your OTP for HD Notes - Verification Code",
    html: `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>OTP Verification - HD Notes</title>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { text-align: center; padding: 20px 0; border-bottom: 2px solid #367AFF; }
          .logo { font-size: 24px; font-weight: bold; color: #367AFF; }
          .content { padding: 30px 0; }
          .otp-box { background: #f8f9fa; border: 2px solid #367AFF; border-radius: 8px; padding: 20px; text-align: center; margin: 20px 0; }
          .otp-code { font-size: 32px; font-weight: bold; color: #367AFF; letter-spacing: 5px; }
          .footer { border-top: 1px solid #eee; padding: 20px 0; text-align: center; color: #666; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <div class="logo">HD Notes</div>
            <p>Your trusted note-taking companion</p>
          </div>
          
          <div class="content">
            <h2>Hello ${name}!</h2>
            <p>Thank you for choosing HD Notes. To complete your verification, please use the OTP code below:</p>
            
            <div class="otp-box">
              <p>Your verification code is:</p>
              <div class="otp-code">${otp}</div>
              <p><small>This code will expire in 10 minutes</small></p>
            </div>
            
            <p>If you didn't request this code, please ignore this email.</p>
            
            <p><strong>Security Tips:</strong></p>
            <ul>
              <li>Never share your OTP with anyone</li>
              <li>This code is valid for 10 minutes only</li>
            </ul>
          </div>
          
          <div class="footer">
            <p>Best regards,<br><strong>HD Notes Team</strong></p>
            <p><small>This is an automated email. Please do not reply to this message.</small></p>
          </div>
        </div>
      </body>
      </html>
    `,
  }

  try {
    console.log(`📧 Attempting to send OTP to ${email}`)
    const result = await transporter.sendMail(mailOptions)
    console.log(`✅ OTP email sent successfully to ${email}`)
    console.log("📧 Message ID:", result.messageId)
  } catch (error) {
    console.error("❌ Detailed email error:", error)
    throw new Error("Failed to send OTP email")
  }
}

export const sendWelcomeEmail = async (email: string, name: string) => {
  const mailOptions = {
    from: process.env.EMAIL_FROM || "satyavalapula@gmail.com",
    to: email,
    subject: "Welcome to HD Notes! 🎉",
    html: `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Welcome to HD Notes</title>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { text-align: center; padding: 20px 0; border-bottom: 2px solid #367AFF; }
          .logo { font-size: 24px; font-weight: bold; color: #367AFF; }
          .content { padding: 30px 0; }
          .welcome-box { background: linear-gradient(135deg, #367AFF, #4A90E2); color: white; border-radius: 12px; padding: 30px; text-align: center; margin: 20px 0; }
          .footer { border-top: 1px solid #eee; padding: 20px 0; text-align: center; color: #666; }
          .feature { background: #f8f9fa; border-radius: 8px; padding: 15px; margin: 10px 0; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <div class="logo">HD Notes</div>
            <p>Your trusted note-taking companion</p>
          </div>
          
          <div class="content">
            <div class="welcome-box">
              <h2>🎉 Welcome to HD Notes, ${name}!</h2>
              <p>Your account has been successfully created and verified.</p>
            </div>
            
            <h3>What you can do with HD Notes:</h3>
            
            <div class="feature">
              <h4>📝 Create & Organize Notes</h4>
              <p>Write, edit, and organize your thoughts with our intuitive interface.</p>
            </div>
            
            <div class="feature">
              <h4>🔍 Search & Find</h4>
              <p>Quickly find any note with our powerful search functionality.</p>
            </div>
            
            <div class="feature">
              <h4>📱 Access Anywhere</h4>
              <p>Your notes are synced across all your devices for seamless access.</p>
            </div>
            
            <p>Ready to get started? Log in to your account and create your first note!</p>
          </div>
          
          <div class="footer">
            <p>Best regards,<br><strong>HD Notes Team</strong></p>
            <p>Need help? Contact us for support.</p>
          </div>
        </div>
      </body>
      </html>
    `,
  }

  try {
    await transporter.sendMail(mailOptions)
    console.log(`✅ Welcome email sent to ${email}`)
  } catch (error) {
    console.error("❌ Error sending welcome email:", error)
  }
}
