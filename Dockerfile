# syntax=docker/dockerfile:1

# ---- Construction : tests, typecheck, application web et commande CI ----
FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN npm test && npm run build

# ---- Commande CI : docker run --rm -v "$PWD:/work" <image-cli> firewall.conf --sarif out.sarif ----
FROM node:22-alpine AS cli
WORKDIR /work
COPY --from=build /app/dist-cli/tamisor.mjs /usr/local/lib/tamisor.mjs
USER node
ENTRYPOINT ["node", "/usr/local/lib/tamisor.mjs"]

# ---- Application web : fichiers statiques servis par nginx, sans root (image par défaut) ----
FROM nginxinc/nginx-unprivileged:1.27-alpine AS web
COPY docker/nginx.conf /etc/nginx/conf.d/default.conf
COPY docker/security-headers.conf /etc/nginx/snippets/security-headers.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --retries=3 CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1

