FROM node:24-alpine

WORKDIR /app

# Install Nmap and its runtime data
RUN apk add --no-cache \
    nmap \
    nmap-scripts \
    curl

# Make sure Nmap can find its NSE data
ENV NMAPDIR=/usr/share/nmap

COPY package*.json ./

RUN npm install

COPY . .

EXPOSE 5000

CMD ["node", "server.js"]