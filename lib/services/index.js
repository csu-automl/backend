const AuthService = require('./lib/AuthService')
const TestService = require('./lib/TestService')

module.exports = {
  authService: new AuthService(),
  testService: new TestService()
}
