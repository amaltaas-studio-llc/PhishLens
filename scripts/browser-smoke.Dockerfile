# Chromium and Firefox ESR for `npm run smoke:docker`, so the browser smoke test needs nothing on the host
# but Docker. Debian's packages rather than builds downloaded by a test framework: they come signed by the
# distribution, and Firefox ESR is the release line the Firefox build's minimum version is pinned to.
#
# Node 24, the LTS the CI package job builds with, so the container builds what CI ships. A major number
# rather than the floating `lts` tag, which moves to a new major on its own and would change this image
# with no change to this file.
FROM node:24-bookworm-slim

# Fonts, because a headless browser with none lays text out in a fallback whose metrics hide or invent
# overflow, which is exactly what the layout checks look for.
RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    chromium firefox-esr fonts-dejavu-core fonts-liberation fonts-noto-color-emoji \
  && rm -rf /var/lib/apt/lists/*

USER node
WORKDIR /repo

# Installed inside the image, never mounted from the host: esbuild ships a native binary per platform, so
# a node_modules from Windows or macOS does not run here.
COPY --chown=node:node package.json package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund

COPY --chown=node:node . .
CMD ["sh", "-c", "npm run build && npm run build:firefox && node scripts/browser-smoke.mjs --browsers=chromium,firefox"]
