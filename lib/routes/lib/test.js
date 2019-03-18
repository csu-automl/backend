const express = require('express')
const router = express.Router()

const { wrap } = requireRoot('lib/utils')
const { authenticate } = require('./middleware')
const { testService } = requireRoot('lib/services')

router.route('/')
  .get(wrap(async (req, res, next) => {
    const models = await testService.listModels()
    res.json(models)
  }))
  .post(authenticate, wrap(async (req, res, next) => {
    const newModel = await testService.createTestModel(req.body)
    res.json(newModel)
  }))

module.exports = router
