const express = require('express')
const { wrap } = requireRoot('lib/utils')
const log = getLogger('security')
const { securityService } = requireRoot('lib/services')
const { WebError } = requireRoot('lib/errors')
const { AuthorizationTokenRequest, RecoverPasswordRequest, RecoverRequest, SignInRequest, SignUpConfirmRequest, SignUpRequest } = requireRoot('lib/models')

const router = express.Router()

router.post('/login', wrap(async (req, res, next) => {
  const request = new SignInRequest(req.body)
  try {
    const token = await securityService.login(request)
    res.send({
      token: token.token,
      user: {
        _id: token.user._id,
        email: token.user.email,
        name: token.user.name
      }
    })
  } catch (e) {
    if (e instanceof WebError) {
      throw e
    } else {
      log.warn('Unable to signin', e)
      throw new WebError(e.message, 500)
    }
  }
}))

router.post('/recover/:check', wrap(async (req, res, next) => {
  const request = new RecoverPasswordRequest(req.body)
  try {
    const token = await securityService.confirm({
      check: req.params.check
    })

    token.user.password = request.password
    token.user.save()

    res.send({
      token: token.token,
      user: {
        _id: token.user._id,
        email: token.user.email,
        name: token.user.name
      }
    })
  } catch (e) {
    if (e instanceof WebError) {
      throw e
    } else {
      log.warn('Unable to recover', e)
      throw new WebError(e.message, 500)
    }
  }
}))

router.post('/token', wrap(async (req, res, next) => {
  const request = new AuthorizationTokenRequest(req.body)
  try {
    const token = await securityService.client(request)

    res.send({
      token: token.token,
      user: {
        _id: token.user._id,
        email: token.user.email,
        name: token.user.name
      }
    })
  } catch (e) {
    if (e instanceof WebError) {
      throw e
    } else {
      log.warn('Unable to create token for User', e)
      throw new WebError(e.message, 500)
    }
  }
}))

router.post('/signup', wrap(async (req, res, next) => {
  const request = new SignUpRequest(req.body)
  try {
    const user = await securityService.signup(request)
    res.json({
      user: {
        _id: user._id,
        email: user.email,
        name: user.name
      }
    })
  } catch (e) {
    if (e instanceof WebError) {
      throw e
    } else {
      if (e.message.indexOf('E11000 duplicate key error collection') >= 0) {
        throw new WebError(e.message, 400)
      }
      log.warn('Unable to signup User', e)
      throw new WebError(e.message, 500)
    }
  }
}))

router.post('/forgot', wrap(async (req, res, next) => {
  const request = new RecoverRequest(req.body)
  try {
    const user = await securityService.forgot(request)

    res.json({
      user: {
        _id: user._id,
        email: user.email
      }
    })
  } catch (e) {
    if (e instanceof WebError) {
      throw e
    } else {
      log.warn('Unable to start recover process', e)
      throw new WebError(e.message, 500)
    }
  }
}))

router.post('/passwd', wrap(async (req, res, next) => {
  const { check, password } = req.body
  try {
    const user = await securityService.passwd({
      check,
      password
    })

    res.json({
      user: {
        _id: user._id,
        email: user.email,
        name: user.name
      }
    })
  } catch (e) {
    if (e instanceof WebError) {
      throw e
    } else {
      log.error('Passwd error', e)
      throw new WebError(e.message, 500)
    }
  }
}))

router.get('/confirm/:check', wrap(async (req, res, next) => {
  try {
    const token = await securityService.confirm({
      check: req.params.check
    })

    res.json({
      token: token.token,
      user: {
        _id: token.user._id,
        email: token.user.email,
        name: token.user.name
      }
    })
  } catch (e) {
    if (e instanceof WebError) {
      throw e
    } else {
      log.warn('Unable to confirm User', e)
      throw new WebError(e.message, 500)
    }
  }
}))

router.get('/recover/:check', wrap(async (req, res, next) => {
  const request = new SignUpConfirmRequest(req.params)
  try {
    const { token, check } = await securityService.recover(request)

    res.json({
      check: check.check,
      token: token.token,
      user: {
        _id: check.user._id,
        email: check.user.email,
        name: check.user.name
      }
    })
  } catch (e) {
    if (e instanceof WebError) {
      throw e
    } else {
      log.warn('Unable to recover User', e)
      throw new WebError(e.message, 500)
    }
  }
}))

router.post('/logout', wrap(async (req, res, next) => {
  const { authorization } = req.headers
  try {
    await securityService.logout({
      token: authorization
    })

    res.send({
      ok: true
    })
  } catch (e) {
    if (e instanceof WebError) {
      throw e
    } else {
      log.warn('Unable to logout User', e)
      throw new WebError(e.message, 500)
    }
  }
}))

module.exports = router
