module.exports = {
  apps: [
    {
      name: 'auth',
      script: 'bin/www',
      env: {
        watch: true,
        PORT: 3001,
        NODE_ENV: 'development'
      },
      env_production: {
        watch: false,
        PORT: 3000,
        NODE_ENV: 'production'
      }
    }
  ]
}
