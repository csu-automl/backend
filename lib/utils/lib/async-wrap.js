module.exports = function (fn) {
  if (fn.length <= 3) {
    return function (req, res, next) {
      return fn(req, res, next).catch(next)
    }
  } else {
    return function (err, req, res, next) {
      return fn(err, req, res, next).catch(next)
    }
  }
}
