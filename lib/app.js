const path = require('path')
const keystone = require('keystone')
const config = require('config')

function createApp (options) {
  keystone.init({
    'name': 'backend',
    'brand': 'AutoML Backend',
    'mongo': config.get('storage.url'),
    'module root': path.join(__dirname, '../'),
    'auto update': true,
    'session': true,
    'auth': true,
    'user model': 'User',
    'cookie secret': config.get('keystone.cookieSecret'),
    ...options
  })

  keystone.import('lib/schema')

  keystone.set('cors allow origin', true)

  keystone.set('routes', require('./routes'))

  keystone.set('nav', {
    test: ['test-models']
  })

  keystone.stop = function () {
    keystone.httpServer.close()
    keystone.mongoose.connection.close()
  }

  return keystone
}

exports = module.exports = {
  createApp
}
