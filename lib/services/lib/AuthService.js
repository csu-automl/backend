const keystone = require('keystone')
const axios = require('axios')
const { get } = require('lodash')
const { WebError } = requireRoot('lib/errors')
const log = getLogger('AuthService')
const SecurityUser = keystone.list('SecurityUser').model

const BEARER_PREFIX = 'Bearer '

const auth = axios.create({
  baseURL: config.get('auth.url')
})

class AuthService {
  async token ({ token }) {
    if (!token || token.indexOf(BEARER_PREFIX) !== 0) {
      throw new WebError('Wrong credentials', 401)
    }
    try {
      const { data } = await auth.get('/api/v1/me', {
        headers: {'Authorization': token}
      })
      const user = await this._synchronizeUser(data.user._id, data.user)
      return {
        token: token.substring(BEARER_PREFIX.length),
        user,
        authUser: data.user
      }
    } catch (e) {
      const response = e.response
      if (response == null) {
        throw new WebError('Authorization service is not available.', 503)
      }
      if (response.status !== 500) {
        throw new WebError('Wrong credentials', response.status)
      } else {
        log.warn(`Authorization service returned unexpected code ${response.status}`, response)
        throw new WebError('Authorization service returned unexpected code', 500)
      }
    }
  }

}

module.exports = AuthService
