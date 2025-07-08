import Joi from "joi"

export const signupSchema = Joi.object({
  name: Joi.string().min(2).max(50).required(),
  email: Joi.string().email().required(),
  dateOfBirth: Joi.date().max("now").required(),
})

export const verifyOTPSchema = Joi.object({
  email: Joi.string().email().required(),
  otp: Joi.string()
    .length(6)
    .pattern(/^[0-9]+$/)
    .required(),
})

export const signinSchema = Joi.object({
  email: Joi.string().email().required(),
  otp: Joi.string()
    .length(6)
    .pattern(/^[0-9]+$/)
    .required(),
})

export const resendOTPSchema = Joi.object({
  email: Joi.string().email().required(),
})
