module.exports = {
  apps: [
    {
      name: 'backend',
      script: 'bin/www',
      env: {
        watch: true,
        PORT: 3000,
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
