FROM node:20-bookworm-slim AS base

# deps stage: install ALL deps (dev + prod) for Next.js build
FROM base AS deps
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci

# builder stage: build Next.js app (standalone output)
FROM base AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
ARG NEXT_PUBLIC_TEE_API
ENV NEXT_PUBLIC_TEE_API=$NEXT_PUBLIC_TEE_API
RUN npm run build

# runtime stage: run the standalone server
FROM base AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV PORT=3000
RUN addgroup --system --gid 1001 nodejs && adduser --system --uid 1001 nextjs
COPY --from=builder /app/public ./public
# Ensure .next directory exists and permissions are set
RUN mkdir -p .next && chown nextjs:nodejs .next
# Copy standalone server and static assets
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static
USER nextjs
EXPOSE 3000
ENV HOSTNAME="0.0.0.0"
CMD ["node", "server.js"]
