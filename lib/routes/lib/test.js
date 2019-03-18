const express = require('express')
const router = express.Router()

const { wrap } = requireRoot('lib/utils')
const { testService } = requireRoot('lib/services')

router.route('/')
  .get(wrap(async (req, res, next) => {
    const models = await testService.listModels()
    res.json(models)
  }))

module.exports = router
