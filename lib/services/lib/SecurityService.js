const keystone = require('keystone')
const config = require('config')
const { promisify } = require('util')
const { WebError } = requireRoot('lib/errors')
const { confirmTemplate, recoverTemplate } = requireRoot('mail')
const { Message } = requireRoot('lib/mail')

const SecurityUser = keystone.list('SecurityUser').model
const SecurityClient = keystone.list('SecurityClient').model
const SecurityToken = keystone.list('SecurityToken').model
const SecurityCheck = keystone.list('SecurityCheck').model

const BEARER_PREFIX = 'Bearer '
const BEARER_PREFIX_LENGTH = BEARER_PREFIX.length

function isUrlAcceptable (baseURL) {
  const acceptedUrls = config.get('mail.acceptedUrls')
  for (let basePath of acceptedUrls) {
    if (baseURL.indexOf(basePath) === 0) {
      return true
    }
  }
  return false
}

class SecurityService {
  async signup ({ name, email, password, baseURL }) {
    if (!isUrlAcceptable(baseURL)) {
      throw new WebError(`Url ${baseURL} is not acceptable.`, 400)
    }
    const user = await SecurityUser.create({
      name,
      email,
      password,
      isConfirmed: false
    })
    const check = await SecurityCheck.create({
      user: user,
      type: 'confirm'
    })
    const { subject, content } = confirmTemplate({
      baseURL: baseURL,
      username: email,
      check: check.check
    })
    const message = new Message({
      to: email,
      subject,
      html: content
    })
    await message.send()
    return user
  }

  async forgot ({ email, baseURL }) {
    if (!isUrlAcceptable(baseURL)) {
      throw new WebError(`Url ${baseURL} is not acceptable.`, 400)
    }
    const user = await SecurityUser.findOne({
      email
    }).exec()
    if (!user) {
      throw new WebError('User not found.', 404)
    }
    const check = await SecurityCheck.create({
      user: user,
      type: 'recover'
    })
    const { subject, content } = recoverTemplate({
      baseURL: baseURL,
      username: email,
      check: check.check
    })
    const message = new Message({
      to: email,
      subject,
      html: content
    })
    await message.send()
    return user
  }

  async passwd ({ check, password }) {
    const c = await SecurityCheck.findOne({
      check,
      type: 'recover'
    }).populate('user')
    if (!c || !c.user) {
      throw new WebError('Security check not found.', 404)
    }
    c.user.password = password
    await c.user.save()
    await SecurityCheck.remove(c)
    return c.user
  }

  async confirm ({ check }) {
    const c = await SecurityCheck.findOne({
      check,
      type: 'confirm'
    }).populate('user')
    if (!c || !c.user) {
      throw new WebError('Security check not found.', 404)
    }
    c.user.isConfirmed = true
    await c.user.save()
    await SecurityCheck.remove(c)
    const token = await SecurityToken.create({
      user: c.user
    })
    return SecurityToken.findOne({
      _id: token._id
    }).populate('user')
      .exec()
  }

  async recover ({ check }) {
    const c = await SecurityCheck.findOne({
      check,
      type: 'recover'
    }).populate('user')
    if (!c || !c.user) {
      throw new WebError('Security check not found.', 404)
    }
    c.user.isConfirmed = true
    await c.user.save()
    const user = c.user
    await SecurityCheck.remove(c)
    const r = await SecurityCheck.create({
      user,
      type: 'recover'
    })
    const token = await SecurityToken.create({
      user: c.user
    })
    const t = await SecurityToken.findOne({
      _id: token._id
    }).populate('user')
      .exec()

    return {
      check: r,
      token: t
    }
  }

  async login ({ email, password }) {
    const user = await SecurityUser.findOne({ email }).exec()
    if (!user || !user.isConfirmed) {
      throw new WebError('Wrong credentials', 400)
    }
    if (!await promisify(user._.password.compare)(password)) {
      throw new WebError('Wrong credentials', 400)
    }
    const token = await SecurityToken.create({
      user: user
    })
    return SecurityToken.findOne({
      _id: token._id
    }).populate('user')
      .exec()
  }

  async client ({ clientId, clientSecret, userId }) {
    const client = await SecurityClient.findOne({
      _id: clientId,
      secret: clientSecret
    }).populate('user')
      .exec()
    if (!client || !client.user || !client.user.isConfirmed) {
      throw new WebError('Wrong credentials', 401)
    }
    const user = (userId != null && client.user.isAdmin)
      ? await SecurityUser.findOne({ _id: userId })
      : client.user
    const token = await SecurityToken.create({
      user
    })
    return SecurityToken.findOne({
      _id: token._id
    }).populate('user')
      .exec()
  }

  async token ({ token }) {
    if (token.indexOf(BEARER_PREFIX) !== 0) {
      throw new WebError('Wrong credentials', 401)
    }
    const securityToken = await SecurityToken.findOne({
      token: token.substring(BEARER_PREFIX_LENGTH)
    }).populate('user')
      .exec()
    if (!securityToken || !securityToken.user) {
      throw new WebError('Wrong credentials', 401)
    }
    return securityToken
  }

  async logout ({ token }) {
    if (token.indexOf('Bearer ') !== 0) {
      throw new WebError('Wrong credentials', 401)
    }
    const result = await SecurityToken.findOne({
      token: token.substring('Bearer '.length)
    }).populate('user')
      .exec()
    if (!result) {
      throw new WebError('Wrong credentials', 401)
    }
    result.remove()
    return result
  }
}

module.exports = SecurityService
