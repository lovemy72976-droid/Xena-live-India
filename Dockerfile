FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production
ENV PORT=10000
COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund
COPY server.js ./
COPY public ./public
COPY sql ./sql
COPY .env.example ./
RUN mkdir -p /app/data && chmod 700 /app/data
EXPOSE 10000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD wget -qO- http://127.0.0.1:${PORT}/health || exit 1
CMD ["node", "server.js"]
