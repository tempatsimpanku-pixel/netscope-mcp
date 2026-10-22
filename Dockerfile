# syntax=docker/dockerfile:1
FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.json tsconfig.build.json ./
RUN npm ci --ignore-scripts
COPY src ./src
RUN npm run build && npm prune --omit=dev --ignore-scripts

FROM node:22-alpine
# ssh client is only used for the optional `export` path over SSH.
RUN apk add --no-cache openssh-client
ENV NODE_ENV=production
WORKDIR /app
COPY --from=build /app/package.json ./package.json
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY routers.example.yaml ./routers.example.yaml
# Non-root; the only writable locations are /tmp and the state dir (mount as tmpfs or a volume).
ENV XDG_STATE_HOME=/tmp/state HOME=/tmp
USER node
ENTRYPOINT ["node", "/app/dist/cli.js"]
CMD ["--help"]
