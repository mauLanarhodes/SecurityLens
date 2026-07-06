# Front-end image: build the Vite bundle, serve it with nginx.
# nginx also reverse-proxies /api to the backend with SSE buffering disabled.
FROM node:20-bookworm AS build
WORKDIR /web
COPY package.json package-lock.json* ./
RUN npm ci || npm install
COPY . .
RUN npm run build

FROM nginx:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /web/dist /usr/share/nginx/html
EXPOSE 80
