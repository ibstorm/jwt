FROM node:22-alpine

WORKDIR /app

COPY package.json /app

RUN npm install --production

COPY . /app

EXPOSE 80

CMD ["node", "server.js"]