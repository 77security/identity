# Use Node.js LTS (Long Term Support) on Alpine for a small footprint
FROM node:20-alpine

# Create app directory
WORKDIR /usr/src/app

# Install app dependencies
# A wildcard is used to ensure both package.json AND package-lock.json are copied
COPY package*.json ./

# Install production dependencies only
RUN npm ci --only=production

# Bundle app source
COPY . .

# The API runs on port 8080 by default
EXPOSE 8080

# Use a non-root user for security
USER node

CMD [ "node", "src/server.js" ]
