// OWASP Threat Model Library - Threat Patterns Database
const threatLibrary = {
  library: {
    version: '1.0.0',
    source: 'OWASP Threat Model Library',
    patterns: {
      'actor': [
        {
          id: 'ACT01',
          title: 'Malicious External Actor',
          description: 'External entities may be compromised or act with malicious intent',
          category: 'Actor Threat',
          stride: ['Spoofing', 'Repudiation'],
          severity: 'High',
          impact: 'Critical',
          targets: ['external_entity', 'user', 'actor'],
          mitigations: [
            'Implement multi-factor authentication',
            'Use digital signatures and certificates',
            'Implement continuous monitoring and anomaly detection',
            'Maintain detailed audit logs',
            'Implement rate limiting and CAPTCHA'
          ],
          references: ['A07:2021 – Identification and Authentication Failures'],
          owaspCategory: 'A07:2021 – Identification and Authentication Failures'
        },
        {
          id: 'ACT02',
          title: 'Account Compromise',
          description: 'Actor credentials may be stolen or compromised',
          category: 'Authentication',
          stride: ['Spoofing'],
          severity: 'High',
          impact: 'High',
          targets: ['external_entity', 'actor'],
          mitigations: [
            'Enforce strong password policies',
            'Implement MFA/2FA',
            'Monitor for suspicious login patterns',
            'Session timeout policies',
            'Password reset procedures'
          ],
          owaspCategory: 'A07:2021 – Identification and Authentication Failures'
        }
      ],
      'process': [
        {
          id: 'PROC01',
          title: 'Input Validation Bypass',
          description: 'Process may not properly validate input, leading to injection attacks',
          category: 'Input Validation',
          stride: ['Tampering'],
          severity: 'Critical',
          impact: 'Critical',
          targets: ['process'],
          mitigations: [
            'Implement strict input validation',
            'Use parameterized queries',
            'Whitelist acceptable input patterns',
            'Use security frameworks (ESAPI, Spring Security)',
            'Regular security testing (SAST)'
          ],
          owaspCategory: 'A03:2021 – Injection'
        },
        {
          id: 'PROC02',
          title: 'Privilege Escalation',
          description: 'Process running with excessive privileges may be exploited',
          category: 'Authorization',
          stride: ['Elevation of Privilege'],
          severity: 'High',
          impact: 'Critical',
          targets: ['process'],
          mitigations: [
            'Apply principle of least privilege',
            'Use role-based access control (RBAC)',
            'Regular privilege audits',
            'Separate user and admin interfaces',
            'Monitor privilege usage'
          ],
          owaspCategory: 'A01:2021 – Broken Access Control'
        },
        {
          id: 'PROC03',
          title: 'Broken Authentication',
          description: 'Process authentication mechanisms may be bypassed or compromised',
          category: 'Authentication',
          stride: ['Spoofing'],
          severity: 'Critical',
          impact: 'Critical',
          targets: ['process'],
          mitigations: [
            'Implement secure authentication protocols (OAuth 2.0, OIDC)',
            'Use hardware security modules for key storage',
            'Implement account lockout mechanisms',
            'Use secure session management',
            'Regular authentication testing'
          ],
          owaspCategory: 'A07:2021 – Identification and Authentication Failures'
        },
        {
          id: 'PROC04',
          title: 'Business Logic Bypass',
          description: 'Application business logic may be bypassed or exploited',
          category: 'Business Logic',
          stride: ['Tampering'],
          severity: 'High',
          impact: 'High',
          targets: ['process'],
          mitigations: [
            'Comprehensive business logic testing',
            'State machine validation',
            'Rate limiting on critical operations',
            'Transaction integrity checks',
            'Fraud detection systems'
          ],
          owaspCategory: 'A04:2021 – Insecure Design'
        }
      ],
      'datastore': [
        {
          id: 'DS01',
          title: 'Unauthorized Data Access',
          description: 'Sensitive data in datastore may be accessed without proper authorization',
          category: 'Information Disclosure',
          stride: ['Information Disclosure'],
          severity: 'Critical',
          impact: 'Critical',
          targets: ['datastore', 'database'],
          mitigations: [
            'Implement database encryption (TDE, field-level encryption)',
            'Use access control lists and row-level security',
            'Implement database auditing and monitoring',
            'Use data masking for sensitive fields',
            'Regular backup and recovery testing',
            'Implement principle of least privilege for DB access'
          ],
          owaspCategory: 'A01:2021 – Broken Access Control'
        },
        {
          id: 'DS02',
          title: 'Data Tampering',
          description: 'Data in datastore may be modified without detection',
          category: 'Data Integrity',
          stride: ['Tampering'],
          severity: 'High',
          impact: 'High',
          targets: ['datastore', 'database'],
          mitigations: [
            'Implement database integrity checks (hash verification)',
            'Use digital signatures for critical data',
            'Enable transaction logging',
            'Implement audit trails',
            'Regular integrity audits',
            'Backup and version control'
          ],
          owaspCategory: 'A06:2021 – Vulnerable and Outdated Components'
        },
        {
          id: 'DS03',
          title: 'Data Loss',
          description: 'Data in datastore may be lost due to failure or attack',
          category: 'Availability',
          stride: ['Denial of Service'],
          severity: 'High',
          impact: 'Critical',
          targets: ['datastore', 'database'],
          mitigations: [
            'Implement automated backups',
            'Use database replication and clustering',
            'Disaster recovery planning',
            'Regular backup testing and restore drills',
            'Implement redundancy',
            'Geographic data distribution'
          ],
          owaspCategory: 'A06:2021 – Vulnerable and Outdated Components'
        },
        {
          id: 'DS04',
          title: 'SQL Injection via Database',
          description: 'Database may be vulnerable to SQL injection attacks',
          category: 'Injection',
          stride: ['Tampering'],
          severity: 'Critical',
          impact: 'Critical',
          targets: ['datastore', 'database'],
          mitigations: [
            'Use parameterized queries and prepared statements',
            'Input validation and sanitization',
            'Principle of least privilege for database accounts',
            'Web Application Firewall (WAF)',
            'Regular security testing (DAST)',
            'Database activity monitoring'
          ],
          owaspCategory: 'A03:2021 – Injection'
        }
      ],
      'dataflow': [
        {
          id: 'DF01',
          title: 'Man-in-the-Middle Attack',
          description: 'Unencrypted dataflow is vulnerable to interception and modification',
          category: 'Network Attack',
          stride: ['Tampering', 'Information Disclosure', 'Spoofing'],
          severity: 'Critical',
          impact: 'Critical',
          appliesToDataflow: true,
          protocols: ['HTTP', 'FTP', 'SMTP', 'TELNET'],
          mitigations: [
            'Use TLS 1.2+ for all communications',
            'Implement certificate pinning',
            'HSTS headers',
            'Perfect forward secrecy',
            'Regular certificate updates',
            'Monitor for suspicious certificates'
          ],
          owaspCategory: 'A02:2021 – Cryptographic Failures'
        },
        {
          id: 'DF02',
          title: 'Eavesdropping',
          description: 'Sensitive data in dataflow may be eavesdropped',
          category: 'Information Disclosure',
          stride: ['Information Disclosure'],
          severity: 'High',
          impact: 'High',
          appliesToDataflow: true,
          mitigations: [
            'End-to-end encryption',
            'Use VPN for sensitive communications',
            'Message-level encryption',
            'Perfect forward secrecy',
            'Regular encryption audits'
          ],
          owaspCategory: 'A02:2021 – Cryptographic Failures'
        },
        {
          id: 'DF03',
          title: 'Replay Attack',
          description: 'Legitimate dataflow messages may be captured and replayed',
          category: 'Network Attack',
          stride: ['Spoofing', 'Tampering'],
          severity: 'High',
          impact: 'High',
          appliesToDataflow: true,
          mitigations: [
            'Implement message timestamps',
            'Use nonce/challenge-response',
            'Session tokens with expiration',
            'Message sequence numbers',
            'MAC codes on messages'
          ],
          owaspCategory: 'A02:2021 – Cryptographic Failures'
        },
        {
          id: 'DF04',
          title: 'Denial of Service',
          description: 'Dataflow may be targeted by DoS attacks',
          category: 'Availability',
          stride: ['Denial of Service'],
          severity: 'Medium',
          impact: 'High',
          appliesToDataflow: true,
          mitigations: [
            'Rate limiting',
            'Load balancing',
            'DDoS protection services',
            'Input validation',
            'Connection timeouts',
            'Resource quotas'
          ],
          owaspCategory: 'A05:2021 – Broken Access Control'
        }
      ],
      'external_entity': [
        {
          id: 'EXT01',
          title: 'Compromised Third-Party',
          description: 'External entity may be compromised or unreliable',
          category: 'Third-Party Risk',
          stride: ['Spoofing', 'Tampering'],
          severity: 'High',
          impact: 'High',
          targets: ['external_entity'],
          mitigations: [
            'Vendor security assessments',
            'Contract security requirements',
            'API authentication and rate limiting',
            'Monitor third-party communications',
            'Incident response plans',
            'Business continuity planning'
          ],
          owaspCategory: 'A06:2021 – Vulnerable and Outdated Components'
        }
      ]
    }
  },

  getThreatPatterns(elementType) {
    const typeMap = {
      'process': 'process',
      'datastore': 'datastore',
      'database': 'datastore',
      'actor': 'actor',
      'external_entity': 'external_entity',
      'user': 'actor',
      'dataflow': 'dataflow'
    };

    const mappedType = typeMap[elementType] || elementType;
    return this.library.patterns[mappedType] || [];
  },

  getThreatById(id) {
    for (const category in this.library.patterns) {
      const found = this.library.patterns[category].find(p => p.id === id);
      if (found) return found;
    }
    return null;
  },

  searchThreats(query) {
    const results = [];
    const lowerQuery = query.toLowerCase();

    for (const category in this.library.patterns) {
      this.library.patterns[category].forEach(pattern => {
        if (
          pattern.title.toLowerCase().includes(lowerQuery) ||
          pattern.description.toLowerCase().includes(lowerQuery) ||
          pattern.category.toLowerCase().includes(lowerQuery)
        ) {
          results.push({ ...pattern, category });
        }
      });
    }

    return results;
  },

  getThreatsByCategory(category) {
    const results = [];
    for (const type in this.library.patterns) {
      const threats = this.library.patterns[type].filter(p => 
        p.category.toLowerCase() === category.toLowerCase()
      );
      results.push(...threats);
    }
    return results;
  },

  getThreatsBySTRIDE(strideCategory) {
    const results = [];
    for (const type in this.library.patterns) {
      this.library.patterns[type].forEach(pattern => {
        if (pattern.stride && pattern.stride.includes(strideCategory)) {
          results.push(pattern);
        }
      });
    }
    return results;
  },

  getLibraryMetadata() {
    const metadata = {
      version: this.library.version,
      source: this.library.source,
      categories: new Set(),
      totalPatterns: 0,
      strideCoverage: new Set(),
      supportedElementTypes: []
    };

    const types = new Set();

    for (const category in this.library.patterns) {
      types.add(category);
      this.library.patterns[category].forEach(pattern => {
        metadata.totalPatterns++;
        metadata.categories.add(pattern.category);
        if (pattern.stride) {
          pattern.stride.forEach(s => metadata.strideCoverage.add(s));
        }
      });
    }

    metadata.supportedElementTypes = Array.from(types);
    metadata.categories = Array.from(metadata.categories);
    metadata.strideCoverage = Array.from(metadata.strideCoverage);

    return metadata;
  }
};

export default threatLibrary;
