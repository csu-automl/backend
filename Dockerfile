FROM node:10-alpine as build

WORKDIR /usr/src/app
COPY . /usr/src/app
ENV NODE_ENV=production

RUN apk add --no-cache make gcc g++ python build-base
RUN yarn install --production

FROM keymetrics/pm2:10-alpine
COPY --from=build /usr/src/app /usr/app
WORKDIR /usr/app
VOLUME /usr/app/config
VOLUME /root/.pm2/logs
EXPOSE 3000/tcp
CMD ["pm2-runtime", "--env", "production", "ecosystem.config.js"]
