FROM node:20-alpine

WORKDIR /app

COPY package*.json ./

RUN npm install --omit=dev

COPY server.js ./
COPY public ./public

RUN mkdir -p /var/lib/sendinator/uploads

ENV NODE_ENV=production
ENV PORT=3000
ENV UPLOAD_DIR=/var/lib/sendinator/uploads
ENV USE_NGINX_ACCEL=false

EXPOSE 3000

RUN addgroup -g 1001 -S sendinator && \
    adduser -S sendinator -u 1001 -G sendinator && \
    chown -R sendinator:sendinator /app /var/lib/sendinator

USER sendinator

CMD ["node", "server.js"]
