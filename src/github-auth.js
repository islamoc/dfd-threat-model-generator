import crypto from 'crypto';
import { Octokit } from '@octokit/rest';

/**
 * Secure GitHub OAuth Token Manager
 * Handles token lifecycle, encryption, and forced authorization
 */
class GitHubAuthManager {
  constructor() {
    this.tokens = new Map(); // userId -> encrypted token + metadata
    this.consentCache = new Map(); // userId+action -> expiry timestamp
    this.CONSENT_TTL_MS = 10 * 60 * 1000; // 10 minutes
  }

  /**
   * Encrypt token before storage
   */
  encryptToken(token, encryptionKey = process.env.GITHUB_TOKEN_ENCRYPTION_KEY) {
    if (!encryptionKey) {
      throw new Error('GITHUB_TOKEN_ENCRYPTION_KEY not configured');
    }

    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(
      'aes-256-cbc',
      Buffer.from(encryptionKey, 'hex'),
      iv
    );

    let encrypted = cipher.update(token, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    return {
      encrypted,
      iv: iv.toString('hex'),
      timestamp: Date.now()
    };
  }

  /**
   * Decrypt stored token
   */
  decryptToken(encryptedData, encryptionKey = process.env.GITHUB_TOKEN_ENCRYPTION_KEY) {
    if (!encryptionKey) {
      throw new Error('GITHUB_TOKEN_ENCRYPTION_KEY not configured');
    }

    const decipher = crypto.createDecipheriv(
      'aes-256-cbc',
      Buffer.from(encryptionKey, 'hex'),
      Buffer.from(encryptedData.iv, 'hex')
    );

    let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  }

  /**
   * Store GitHub OAuth token securely
   */
  storeToken(userId, token, scopes = []) {
    const encrypted = this.encryptToken(token);
    this.tokens.set(userId, {
      ...encrypted,
      scopes,
      expiresAt: Date.now() + (60 * 60 * 1000) // 1 hour default
    });

    // Log for audit
    console.log(`[AUTH] Token stored for user ${userId} with scopes: ${scopes.join(',')}`);
  }

  /**
   * Retrieve and decrypt token
   */
  getToken(userId) {
    const stored = this.tokens.get(userId);
    if (!stored) {
      return null;
    }

    // Check expiry
    if (stored.expiresAt < Date.now()) {
      this.tokens.delete(userId);
      return null;
    }

    try {
      const token = this.decryptToken({
        encrypted: stored.encrypted,
        iv: stored.iv
      });
      return { token, scopes: stored.scopes };
    } catch (error) {
      console.error(`[AUTH] Failed to decrypt token for user ${userId}:`, error.message);
      this.tokens.delete(userId);
      return null;
    }
  }

  /**
   * Check if user has required scopes
   */
  hasRequiredScopes(userId, requiredScopes) {
    const tokenData = this.tokens.get(userId);
    if (!tokenData) return false;

    return requiredScopes.every(scope => tokenData.scopes.includes(scope));
  }

  /**
   * Grant user consent for an action
   * Marks that user has confirmed this action within TTL window
   */
  grantConsent(userId, action) {
    const key = `${userId}:${action}`;
    this.consentCache.set(key, Date.now() + this.CONSENT_TTL_MS);
    console.log(`[CONSENT] Granted to ${userId} for action '${action}' until ${new Date(Date.now() + this.CONSENT_TTL_MS).toISOString()}`);
  }

  /**
   * Check if user has valid consent for action
   */
  hasValidConsent(userId, action) {
    const key = `${userId}:${action}`;
    const expiry = this.consentCache.get(key);

    if (!expiry) {
      return false;
    }

    if (expiry < Date.now()) {
      this.consentCache.delete(key);
      return false;
    }

    return true;
  }

  /**
   * Create Octokit instance with user's token
   */
  getOctokitClient(userId) {
    const tokenData = this.getToken(userId);
    if (!tokenData) {
      throw new Error('No valid GitHub token found. User must authenticate first.');
    }

    return new Octokit({
      auth: tokenData.token
    });
  }

  /**
   * Revoke user's token
   */
  revokeToken(userId) {
    this.tokens.delete(userId);
    // Clear consent cache for this user
    for (const key of this.consentCache.keys()) {
      if (key.startsWith(`${userId}:`)) {
        this.consentCache.delete(key);
      }
    }
    console.log(`[AUTH] Token revoked for user ${userId}`);
  }

  /**
   * Validate token with GitHub
   */
  async validateToken(token) {
    try {
      const octokit = new Octokit({ auth: token });
      const user = await octokit.rest.users.getAuthenticated();
      return {
        valid: true,
        user: user.data.login,
        scopes: user.headers['x-oauth-scopes']?.split(', ') || []
      };
    } catch (error) {
      return {
        valid: false,
        error: error.message
      };
    }
  }
}

export default new GitHubAuthManager();
