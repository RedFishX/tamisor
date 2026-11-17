# syntax=docker/dockerfile:1

# Les images de base sont épinglées par digest (index multi-architecture) ; Dependabot (.github/dependabot.yml)
# propose les mises à jour. Pour la main : `docker buildx imagetools inspect <image:tag>` donne le digest.

# ---- Construction : tests, typecheck, application web et commande CI ----
# Toujours sur l'architecture native du runner (BUILDPLATFORM) : le résultat est du JavaScript indépendant de la
# plateforme, et émuler arm64 rend les tests de performance (analyse de 5 000 policies) trop lents.
FROM --platform=$BUILDPLATFORM node:22-alpine@sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN npm test && npm run build

# ---- Commande CI : docker run --rm -v "$PWD:/work" <image-cli> firewall.conf --sarif out.sarif ----
FROM node:22-alpine@sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a AS cli
WORKDIR /work
COPY --from=build /app/dist-cli/tamisor.mjs /usr/local/lib/tamisor.mjs
USER node
ENTRYPOINT ["node", "/usr/local/lib/tamisor.mjs"]

# ---- Application web : fichiers statiques servis par nginx, sans root (image par défaut) ----
FROM nginxinc/nginx-unprivileged:1.27-alpine@sha256:65e3e85dbaed8ba248841d9d58a899b6197106c23cb0ff1a132b7bfe0547e4c0 AS web
COPY docker/nginx.conf /etc/nginx/conf.d/default.conf
COPY docker/security-headers.conf /etc/nginx/snippets/security-headers.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --retries=3 CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1

