const { authService } = requireRoot('lib/services')
const { WebError } = requireRoot('lib/errors')

exports.authenticate = (req, res, next) => {
  authService.token({ token: req.headers.authorization })
    .then(token => {
      req.token = token
      if (token === null) {
        next(new WebError('Forbidden', 401))
      }
      next()
    })
    .catch(e => {
      if (e instanceof WebError) {
        next(e)
      } else {
        next(new WebError(e.message, 401))
      }
    })
}
