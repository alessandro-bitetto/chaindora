FROM node:24-alpine@sha256:e67514e5d0f6c46656005e1b693b2ec9d52e80b641307de684d4a015ba7a4eaf
RUN npm install -g pnpm@11.0.9 && npm install --prefix /opt/yarn-berry @yarnpkg/cli-dist@4.18.1
