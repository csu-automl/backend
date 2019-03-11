const keystone = require('keystone')
const log = getLogger('router')

const middlewareRouter = require('./lib/middleware')
const securityRouter = require('./lib/security')
const meRouter = require('./lib/me')

const { WebError, SchemaValidationError } = requireRoot('lib/errors')

keystone.pre('routes', middlewareRouter.initLocals)

function errorHandler (err, req, res, next) {
  let status = 500
  if (err instanceof SchemaValidationError) {
    status = 400
  } else if (err instanceof WebError) {
    status = err.status
  }
  log.debug(`Exception has occured while handling ${req.originalUrl} request`)
  if (typeof req.query === 'object' && Object.keys(req.query).length > 0) {
    log.debug('Request query', req.query)
  }
  if (typeof req.params === 'object' && Object.keys(req.params).length > 0) {
    log.debug('Request params', req.params)
  }
  if (typeof req.body === 'object' && Object.keys(req.body).length > 0) {
    log.debug('Request body', req.body)
  }
  log.debug(err)
  res.status(status).send({ error: err.message })
}

exports = module.exports = function (app) {
  app.set('json spaces', 2)

  app.all('/api/v1/*', keystone.middleware.cors)

  app.options('/api/v1/*', (req, res) => {
    res.sendStatus(200)
  })

  app.use('/api/v1/security', securityRouter)
  app.use('/api/v1/me', meRouter)

  app.get('/', (req, res) => {
    res.redirect('/keystone/')
  })

  app.use(errorHandler)
}
