# Auth

## Prerequisites

1. Install node v10.15.0+, install yarn 1.12.0+

2. Install and launch mongodb service

3. Update these config files:

- config/default.json

## Setup & Run

``` bash
# install dependencies
yarn

# start auth service using development settings
pm2 start ecosystem.config.js

# start auth service using production settings
pm2 start ecosystem.config.js --env production

# stop auth service
pm2 stop ecosystem.config.js
```
