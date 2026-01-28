import express from 'express';
import multer from 'multer';
import diagramRecognizer from './diagram-recognizer.js';
import gitHubRepoManager from './github-repo-manager.js';
import gitHubAuthManager from './github-auth.js';
import threatGenerator from './threatGenerator.js';
import dfdValidator from './dfdValidator.js';

const router = express.Router();
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
  fileFilter: (req, file, cb) => {
    const allowedMimes = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];
    if (allowedMimes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed (JPEG, PNG, WebP, GIF)'));
    }
  }
});

/**
 * GET /api/health
 * Health check endpoint
 */
router.get('/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

/**
 * POST /api/diagrams/import-from-image
 * Import DFD from image (PNG, JPEG, WebP)
 */
router.post('/diagrams/import-from-image', upload.single('image'), async (req, res) => {
  try {
    if (!req.file && !req.body.imageUrl) {
      return res.status(400).json({
        error: 'Image file or URL required',
        message: 'Provide image as multipart form data or imageUrl in body'
      });
    }

    const diagramType = req.body.diagramType || 'dfd';
    const imageInput = req.file ? req.file.buffer : req.body.imageUrl;

    console.log(`[IMPORT] Starting diagram recognition for type: ${diagramType}`);

    const dfdData = await diagramRecognizer.recognizeDiagram(imageInput, diagramType);

    // Validate extracted DFD
    const validation = dfdValidator.validate(dfdData);
    if (!validation.valid) {
      return res.status(400).json({
        success: false,
        error: 'Extracted diagram failed validation',
        validationErrors: validation.errors,
        dfd: dfdData // Return the data anyway for manual review
      });
    }

    res.json({
      success: true,
      message: 'Diagram successfully imported from image',
      dfd: dfdData,
      validation: validation
    });
  } catch (error) {
    console.error('[IMPORT] Error:', error.message);
    res.status(500).json({
      success: false,
      error: 'Failed to process diagram',
      details: error.message
    });
  }
});

/**
 * POST /api/diagrams/import-and-push
 * Import diagram from image AND push to GitHub in one operation
 */
router.post('/diagrams/import-and-push', upload.single('image'), async (req, res) => {
  try {
    const { userId, owner, repo, branch = 'main', message } = req.body;

    if (!userId) {
      return res.status(401).json({ error: 'User ID required' });
    }

    if (!req.file && !req.body.imageUrl) {
      return res.status(400).json({ error: 'Image file or URL required' });
    }

    // Step 1: Recognize diagram from image
    console.log(`[IMPORT-PUSH] Starting diagram import for user ${userId}`);

    const imageInput = req.file ? req.file.buffer : req.body.imageUrl;
    const diagramType = req.body.diagramType || 'dfd';

    const dfdData = await diagramRecognizer.recognizeDiagram(imageInput, diagramType);

    // Validate
    const validation = dfdValidator.validate(dfdData);
    if (!validation.valid) {
      return res.status(400).json({
        success: false,
        error: 'Extracted diagram failed validation',
        validationErrors: validation.errors
      });
    }

    // Step 2: Generate threat model from imported DFD
    console.log(`[IMPORT-PUSH] Generating threat model...`);
    const threatModel = threatGenerator.generateThreatModel(dfdData, {});

    // Step 3: Push to GitHub with forced authorization
    console.log(`[IMPORT-PUSH] Pushing to GitHub: ${owner}/${repo}`);

    const pushResult = await gitHubRepoManager.pushDFDToRepository(
      userId,
      dfdData,
      {
        owner,
        repo,
        branch,
        path: 'diagrams/imported-dfd.json',
        message: message || `Import DFD from image: ${dfdData.name}`
      }
    );

    if (!pushResult.success) {
      // Check if authorization is needed
      if (pushResult.requiresAuth || pushResult.requiresConsent) {
        return res.status(401).json({
          success: false,
          ...pushResult,
          diagramData: dfdData // Return diagram for client to retry
        });
      }
      return res.status(400).json(pushResult);
    }

    res.json({
      success: true,
      message: 'Diagram imported from image and pushed to GitHub',
      dfd: dfdData,
      threatModel: {
        summary: {
          totalElements: dfdData.elements.length,
          totalDataflows: dfdData.dataflows.length,
          threatsIdentified: threatModel.threats.length
        }
      },
      github: pushResult
    });
  } catch (error) {
    console.error('[IMPORT-PUSH] Error:', error.message);
    res.status(500).json({
      success: false,
      error: 'Import and push operation failed',
      details: error.message
    });
  }
});

/**
 * POST /api/github/auth/consent
 * Grant user consent for a GitHub operation
 */
router.post('/github/auth/consent', (req, res) => {
  try {
    const { userId, action } = req.body;

    if (!userId || !action) {
      return res.status(400).json({ error: 'userId and action are required' });
    }

    gitHubAuthManager.grantConsent(userId, action);

    res.json({
      success: true,
      message: `Consent granted for action: ${action}`,
      expiresIn: '10 minutes'
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * POST /api/github/auth/token
 * Store GitHub OAuth token securely
 */
router.post('/github/auth/token', (req, res) => {
  try {
    const { userId, token, scopes } = req.body;

    if (!userId || !token) {
      return res.status(400).json({ error: 'userId and token are required' });
    }

    gitHubAuthManager.storeToken(userId, token, scopes || ['repo']);

    res.json({
      success: true,
      message: 'GitHub token stored securely',
      scopes: scopes || ['repo']
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * POST /api/github/validate-token
 * Validate GitHub token
 */
router.post('/github/auth/validate', async (req, res) => {
  try {
    const { token } = req.body;

    if (!token) {
      return res.status(400).json({ error: 'Token required' });
    }

    const validation = await gitHubAuthManager.validateToken(token);

    res.json(validation);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * POST /api/github/push-diagram
 * Push diagram to GitHub repository
 * Requires: userId, owner, repo, dfd data
 */
router.post('/github/push-diagram', async (req, res) => {
  try {
    const { userId, owner, repo, dfd, branch = 'main', message } = req.body;

    if (!userId || !owner || !repo || !dfd) {
      return res.status(400).json({
        error: 'userId, owner, repo, and dfd are required'
      });
    }

    // Validate DFD before pushing
    const validation = dfdValidator.validate(dfd);
    if (!validation.valid) {
      return res.status(400).json({
        success: false,
        error: 'Invalid DFD structure',
        validationErrors: validation.errors
      });
    }

    const result = await gitHubRepoManager.pushDFDToRepository(
      userId,
      dfd,
      {
        owner,
        repo,
        branch,
        path: `diagrams/${dfd.name || 'dfd'}.json`,
        message: message || `Update DFD: ${dfd.name}`
      }
    );

    if (!result.success && (result.requiresAuth || result.requiresConsent)) {
      return res.status(401).json(result);
    }

    if (!result.success) {
      return res.status(400).json(result);
    }

    res.json({
      success: true,
      message: `Diagram pushed to ${owner}/${repo}`,
      ...result
    });
  } catch (error) {
    console.error('[PUSH] Error:', error.message);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * GET /api/github/repositories
 * List user's GitHub repositories
 */
router.get('/github/repositories', async (req, res) => {
  try {
    const { userId } = req.query;

    if (!userId) {
      return res.status(400).json({ error: 'userId query parameter required' });
    }

    const result = await gitHubRepoManager.listUserRepositories(userId);

    if (!result.success && (result.requiresAuth || result.requiresConsent)) {
      return res.status(401).json(result);
    }

    res.json(result);
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * POST /api/github/create-pr
 * Create pull request with diagram changes
 */
router.post('/github/create-pr', async (req, res) => {
  try {
    const { userId, owner, repo, branch, title, description } = req.body;

    if (!userId || !owner || !repo || !branch) {
      return res.status(400).json({
        error: 'userId, owner, repo, and branch are required'
      });
    }

    const result = await gitHubRepoManager.createDiagramPullRequest(
      userId,
      { owner, repo, branch, title, description }
    );

    if (!result.success && (result.requiresAuth || result.requiresConsent)) {
      return res.status(401).json(result);
    }

    res.json(result);
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

export default router;
