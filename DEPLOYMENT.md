# Deployment Guide

## Local Development

### Prerequisites
- Node.js 16 or higher
- npm or yarn
- Git

### Setup

```bash
# Clone repository
git clone https://github.com/islamoc/dfd-threat-model-generator.git
cd dfd-threat-model-generator

# Install dependencies
npm install

# Start development server
npm start
```

Application will be available at `http://localhost:3000`

## Environment Configuration

Create `.env` file in project root:

```env
PORT=3000
NODE_ENV=development
API_BASE_URL=http://localhost:3000
```

## Docker Deployment

### Build Docker Image

```bash
docker build -t dfd-threat-model-generator .
```

### Run Container

```bash
docker run -p 3000:3000 dfd-threat-model-generator
```

### Docker Compose

```bash
docker-compose up -d
```

## Heroku Deployment

```bash
# Login to Heroku
heroku login

# Create Heroku app
heroku create dfd-threat-model-generator

# Deploy
git push heroku main

# View logs
heroku logs --tail
```

## AWS Deployment

### Using Elastic Beanstalk

```bash
# Install EB CLI
pip install awsebcli

# Initialize
eb init -p node.js-14 dfd-threat-model-generator

# Create environment
eb create dfd-env

# Deploy
eb deploy
```

### Using EC2

1. Launch EC2 instance (Ubuntu 20.04 LTS)
2. SSH into instance
3. Install Node.js

```bash
curl -fsSL https://deb.nodesource.com/setup_16.x | sudo -E bash -
sudo apt-get install -y nodejs
```

4. Clone and setup

```bash
git clone https://github.com/islamoc/dfd-threat-model-generator.git
cd dfd-threat-model-generator
npm install
```

5. Start with PM2

```bash
sudo npm install -g pm2
pm2 start server.js --name "dfd-threat-model"
pm2 startup
pm2 save
```

6. Configure Nginx reverse proxy

```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
```

## Azure Deployment

### Using App Service

1. Create resource group
```bash
az group create --name dfd-rg --location "East US"
```

2. Create App Service plan
```bash
az appservice plan create --name dfd-plan --resource-group dfd-rg --sku B1 --is-linux
```

3. Create web app
```bash
az webapp create --resource-group dfd-rg --plan dfd-plan --name dfd-app --runtime "NODE|16-lts"
```

4. Deploy from GitHub
```bash
az webapp deployment source config-zip --resource-group dfd-rg --name dfd-app --src deploy.zip
```

## Google Cloud Deployment

### Using Cloud Run

```bash
# Build image
gcloud builds submit --tag gcr.io/PROJECT_ID/dfd-threat-model

# Deploy
gcloud run deploy dfd-threat-model \
  --image gcr.io/PROJECT_ID/dfd-threat-model \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated
```

## Production Checklist

- [ ] Set `NODE_ENV=production`
- [ ] Enable HTTPS/SSL
- [ ] Configure firewall rules
- [ ] Set up monitoring and logging
- [ ] Configure backup procedures
- [ ] Enable rate limiting
- [ ] Set up health checks
- [ ] Configure auto-scaling
- [ ] Enable CORS for specific origins
- [ ] Configure environment variables securely
- [ ] Set up CDN for static assets
- [ ] Enable gzip compression

## Monitoring

### Application Monitoring

- CPU and memory usage
- Request latency
- Error rates
- API response times

### Logging

Configure logging service:

```javascript
// server.js
const logger = require('winston');

logger.add(new logger.transports.File({ filename: 'error.log', level: 'error' }));
logger.add(new logger.transports.File({ filename: 'combined.log' }));
```

## Security

- Enable HTTPS with valid SSL certificate
- Use strong environment variables
- Implement rate limiting
- Enable CORS with trusted origins only
- Use security headers (helmet.js recommended)
- Regular security updates
- Monitor for vulnerabilities

## Scaling

### Horizontal Scaling

- Use load balancer
- Deploy multiple instances
- Use managed services (Heroku, AWS, Azure, GCP)

### Vertical Scaling

- Increase server resources
- Optimize database queries
- Implement caching (Redis)

## Backup & Recovery

- Regular backups of configuration
- Database backup procedures
- Disaster recovery plan
- Test recovery procedures regularly

## Troubleshooting

### Port Already in Use

```bash
lsof -i :3000
kill -9 <PID>
```

### Memory Issues

```bash
node --max-old-space-size=4096 server.js
```

### High CPU Usage

- Check for inefficient queries
- Review threat generation algorithm
- Consider implementing caching

## Support

For deployment issues, open an issue on GitHub or contact the team.
