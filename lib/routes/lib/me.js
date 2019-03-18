const express = require('express')
const { wrap } = requireRoot('lib/utils')

const { authenticate } = require('./middleware')

const router = express.Router()
router.use(authenticate)

router.get('/', wrap(async (req, res, next) => {
  const token = req.token
  res.send({
    token: token.token,
    user: {
      _id: token.user._id,
      email: token.user.email,
      name: token.user.name
    }
  })
}))

module.exports = router
