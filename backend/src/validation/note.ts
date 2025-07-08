import Joi from "joi"

export const createNoteSchema = Joi.object({
  title: Joi.string().min(1).max(200).required(),
  content: Joi.string().max(10000).allow(""),
  tags: Joi.array().items(Joi.string().max(30)).max(10),
  isPinned: Joi.boolean(),
})

export const updateNoteSchema = Joi.object({
  title: Joi.string().min(1).max(200),
  content: Joi.string().max(10000).allow(""),
  tags: Joi.array().items(Joi.string().max(30)).max(10),
  isPinned: Joi.boolean(),
})
