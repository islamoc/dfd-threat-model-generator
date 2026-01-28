import express from 'express';
import cors from 'cors';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import threatGenerator from './src/threatGenerator.js';
import dfdValidator from './src/dfdValidator.js';
import threatLibrary from './src/threatLibrary.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static(join(__dirname, 'public')));

// Routes

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// Get threat library metadata
app.get('/api/threats/library', (req, res) => {
  try {
    const metadata = threatLibrary.getLibraryMetadata();
    res.json(metadata);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get threat patterns by type
app.get('/api/threats/patterns/:type', (req, res) => {
  try {
    const { type } = req.params;
    const patterns = threatLibrary.getThreatPatterns(type);
    res.json(patterns);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Validate DFD
app.post('/api/dfd/validate', (req, res) => {
  try {
    const { dfd } = req.body;
    const validation = dfdValidator.validate(dfd);
    res.json(validation);
  } catch (error) {
    res.status(400).json({ 
      valid: false, 
      errors: [error.message] 
    });
  }
});

// Generate threat model from DFD
app.post('/api/threats/generate', (req, res) => {
  try {
    const { dfd, options = {} } = req.body;

    // Validate DFD first
    const validation = dfdValidator.validate(dfd);
    if (!validation.valid) {
      return res.status(400).json({ 
        success: false, 
        errors: validation.errors 
      });
    }

    // Generate threats
    const threatModel = threatGenerator.generateThreatModel(dfd, options);

    res.json({
      success: true,
      threatModel,
      summary: {
        totalElements: dfd.elements.length,
        totalDataflows: dfd.dataflows.length,
        threatsIdentified: threatModel.threats.length,
        riskLevels: threatModel.riskSummary
      }
    });
  } catch (error) {
    console.error('Threat generation error:', error);
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});

// Generate detailed threat report
app.post('/api/reports/threat-analysis', (req, res) => {
  try {
    const { dfd, options = {} } = req.body;

    const validation = dfdValidator.validate(dfd);
    if (!validation.valid) {
      return res.status(400).json({ 
        success: false, 
        errors: validation.errors 
      });
    }

    const threatModel = threatGenerator.generateThreatModel(dfd, options);
    const report = threatGenerator.generateReport(threatModel, dfd);

    res.json({
      success: true,
      report
    });
  } catch (error) {
    console.error('Report generation error:', error);
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});

// Export threat model as JSON
app.post('/api/export/json', (req, res) => {
  try {
    const { dfd, threatModel } = req.body;
    
    const export_data = {
      version: '1.0.0',
      schema: 'https://github.com/OWASP/www-project-threat-model-library/blob/v1.0.0/threat-model.schema.json',
      metadata: {
        created: new Date().toISOString(),
        title: dfd.name || 'Threat Model',
        description: dfd.description || ''
      },
      elements: dfd.elements,
      dataflows: dfd.dataflows,
      threatModel,
      exportedAt: new Date().toISOString()
    };

    res.json({
      success: true,
      data: export_data
    });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});

// 404 Handler
app.use((req, res) => {
  res.status(404).json({ error: 'Not Found' });
});

// Error handler
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ 
    error: 'Internal Server Error',
    message: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`🔒 DFD Threat Model Generator running on port ${PORT}`);
  console.log(`📝 API available at http://localhost:${PORT}/api`);
  console.log(`🌐 UI available at http://localhost:${PORT}`);
});
