const express = require('express')
const { wrap } = requireRoot('lib/utils')
const log = getLogger('me')
const { securityService } = requireRoot('lib/services')
const { WebError } = requireRoot('lib/errors')

const authenticate = (req, res, next) => {
  securityService.token({ token: req.headers.authorization })
    .then(token => {
      req.token = token
      if (token === null) {
        next(new WebError('Forbidden', 401))
      }
      next()
    })
    .catch(e => {
      log.debug('Authorization failed', e)
      if (e instanceof WebError) {
        next(e)
      } else {
        next(new WebError(e.message, 401))
      }
    })
}

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
