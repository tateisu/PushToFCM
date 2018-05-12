FROM node:10.1-alpine

ENV NODE_ENV=production

RUN addgroup -g 1001 app1
RUN adduser -u 1001 -G app1 -g 'App1' -D -H app1

RUN mkdir /app1
WORKDIR /app1
ADD . /app1
RUN yarn

USER app1

EXPOSE 4005
CMD ["npm", "start"]
