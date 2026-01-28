import { Octokit } from '@octokit/rest';
import gitHubAuthManager from './github-auth.js';

/**
 * GitHub Repository Manager
 * Handles all GitHub operations with forced authorization checks
 */
class GitHubRepoManager {
  /**
   * Validates authorization before any GitHub operation
   */
  async validateAuthorization(userId, requiredAction, options = {}) {
    // Check if user has valid token
    const tokenData = gitHubAuthManager.getToken(userId);
    if (!tokenData) {
      return {
        authorized: false,
        requiresAuth: true,
        error: 'GitHub authentication required',
        redirectUrl: '/auth/github/login'
      };
    }

    // Check if user has required scopes
    const requiredScopes = this.getRequiredScopes(requiredAction);
    if (!gitHubAuthManager.hasRequiredScopes(userId, requiredScopes)) {
      return {
        authorized: false,
        requiresReauth: true,
        error: `Insufficient scopes. Required: ${requiredScopes.join(', ')}`,
        redirectUrl: '/auth/github/login?scopes=' + requiredScopes.join(',')
      };
    }

    // Check if user has valid consent for this specific action
    if (!gitHubAuthManager.hasValidConsent(userId, requiredAction)) {
      return {
        authorized: false,
        requiresConsent: true,
        error: 'User consent required for this action',
        actionDetails: {
          action: requiredAction,
          description: this.getActionDescription(requiredAction),
          repo: options.repo,
          branch: options.branch || 'main',
          message: options.message
        }
      };
    }

    return { authorized: true };
  }

  /**
   * Get required OAuth scopes for an action
   */
  getRequiredScopes(action) {
    const scopeMap = {
      'push_file': ['repo'],
      'create_branch': ['repo'],
      'create_pr': ['repo'],
      'read_repo': ['repo:read'],
      'write_repo': ['repo']
    };
    return scopeMap[action] || ['repo'];
  }

  /**
   * Get human-readable description of action
   */
  getActionDescription(action) {
    const descriptions = {
      'push_file': 'Push diagram files to your GitHub repository',
      'create_branch': 'Create a new branch for diagram changes',
      'create_pr': 'Create a pull request with diagram updates',
      'read_repo': 'Read repository contents',
      'write_repo': 'Write files to your repository'
    };
    return descriptions[action] || 'GitHub operation';
  }

  /**
   * Push DFD diagram to GitHub repository
   * With forced authorization
   */
  async pushDFDToRepository(userId, diagramData, options = {}) {
    // Validate authorization first
    const authResult = await this.validateAuthorization(
      userId,
      'push_file',
      { repo: options.repo, branch: options.branch, message: options.message }
    );

    if (!authResult.authorized) {
      return {
        success: false,
        ...authResult
      };
    }

    try {
      const octokit = gitHubAuthManager.getOctokitClient(userId);
      const { owner, repo, branch = 'main', path = 'diagrams/dfd-diagram.json' } = options;

      if (!owner || !repo) {
        throw new Error('Repository owner and name are required');
      }

      // Get authenticated user info
      const user = await octokit.rest.users.getAuthenticated();
      const username = user.data.login;

      // Check if branch exists, if not create it
      let baseBranch = 'main';
      try {
        await octokit.rest.repos.getBranch({ owner, repo, branch });
        baseBranch = branch;
      } catch (error) {
        if (error.status === 404) {
          // Branch doesn't exist, get default branch
          const repoData = await octokit.rest.repos.get({ owner, repo });
          baseBranch = repoData.data.default_branch;
        } else {
          throw error;
        }
      }

      // Get base commit for new branch if creating
      let branchRef = branch;
      if (branch !== baseBranch) {
        try {
          const baseRef = await octokit.rest.git.getRef({
            owner,
            repo,
            ref: `heads/${baseBranch}`
          });
          const sha = baseRef.data.object.sha;

          // Create new branch
          await octokit.rest.git.createRef({
            owner,
            repo,
            ref: `refs/heads/${branch}`,
            sha
          });
        } catch (error) {
          if (error.status !== 422) { // 422 = ref already exists
            throw error;
          }
        }
      }

      // Check if file exists
      let fileSha;
      try {
        const existingFile = await octokit.rest.repos.getContent({
          owner,
          repo,
          path,
          ref: branch
        });
        fileSha = existingFile.data.sha;
      } catch (error) {
        if (error.status !== 404) {
          throw error;
        }
        // File doesn't exist, that's fine
      }

      // Prepare file content
      const fileContent = JSON.stringify(diagramData, null, 2);
      const encodedContent = Buffer.from(fileContent).toString('base64');

      // Commit file
      const commitMessage = options.message || `Add/Update DFD diagram: ${diagramData.name || 'diagram'}`;

      const commitResult = await octokit.rest.repos.createOrUpdateFileContents({
        owner,
        repo,
        path,
        message: commitMessage,
        content: encodedContent,
        branch,
        sha: fileSha,
        committer: {
          name: 'DFD Threat Model Generator',
          email: 'noreply@dfdgenerator.dev'
        }
      });

      // Log successful operation
      console.log(`[GITHUB] User ${username} pushed diagram to ${owner}/${repo}:${branch}/${path}`);

      return {
        success: true,
        message: `Diagram pushed successfully to ${owner}/${repo}:${branch}`,
        file: commitResult.data.content,
        commit: commitResult.data.commit
      };
    } catch (error) {
      console.error(`[GITHUB] Push failed for user ${userId}:`, error.message);
      return {
        success: false,
        error: error.message,
        details: error.response?.data?.message
      };
    }
  }

  /**
   * Create pull request with diagram changes
   */
  async createDiagramPullRequest(userId, options = {}) {
    const authResult = await this.validateAuthorization(
      userId,
      'create_pr',
      { repo: options.repo, branch: options.branch }
    );

    if (!authResult.authorized) {
      return {
        success: false,
        ...authResult
      };
    }

    try {
      const octokit = gitHubAuthManager.getOctokitClient(userId);
      const { owner, repo, branch, title, description } = options;

      if (!owner || !repo || !branch) {
        throw new Error('Repository owner, name, and branch are required');
      }

      const prResult = await octokit.rest.pulls.create({
        owner,
        repo,
        title: title || 'Add DFD Diagram',
        body: description || 'New DFD diagram added via Threat Model Generator',
        head: branch,
        base: 'main'
      });

      console.log(`[GITHUB] User ${userId} created PR #${prResult.data.number} for ${owner}/${repo}`);

      return {
        success: true,
        pr: prResult.data,
        url: prResult.data.html_url
      };
    } catch (error) {
      console.error(`[GITHUB] PR creation failed for user ${userId}:`, error.message);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * List user's repositories
   */
  async listUserRepositories(userId) {
    const authResult = await this.validateAuthorization(userId, 'read_repo');

    if (!authResult.authorized) {
      return {
        success: false,
        ...authResult
      };
    }

    try {
      const octokit = gitHubAuthManager.getOctokitClient(userId);
      const repos = await octokit.rest.repos.listForAuthenticatedUser({
        per_page: 100,
        type: 'owner'
      });

      return {
        success: true,
        repositories: repos.data.map(repo => ({
          id: repo.id,
          name: repo.name,
          owner: repo.owner.login,
          fullName: repo.full_name,
          url: repo.html_url,
          defaultBranch: repo.default_branch,
          description: repo.description
        }))
      };
    } catch (error) {
      console.error(`[GITHUB] Failed to list repositories for user ${userId}:`, error.message);
      return {
        success: false,
        error: error.message
      };
    }
  }
}

export default new GitHubRepoManager();
