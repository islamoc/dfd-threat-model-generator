import { v4 as uuidv4 } from 'uuid';
import threatLibrary from './threatLibrary.js';

const threatGenerator = {
  generateThreatModel(dfd, options = {}) {
    const threats = [];
    const elementThreats = new Map();
    const dataflowThreats = new Map();
    const riskSummary = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0
    };

    // Analyze elements (actors, processes, datastores, etc.)
    dfd.elements.forEach(element => {
      const elementThreatList = this.analyzeElement(element, dfd);
      elementThreats.set(element.id, elementThreatList);
      
      elementThreatList.forEach(threat => {
        threat.id = uuidv4();
        threat.elementId = element.id;
        threat.elementName = element.name;
        threat.elementType = element.type;
        threats.push(threat);
        riskSummary[threat.severity.toLowerCase()]++;
      });
    });

    // Analyze dataflows
    dfd.dataflows.forEach(dataflow => {
      const dataflowThreatList = this.analyzeDataflow(dataflow, dfd);
      dataflowThreats.set(dataflow.id, dataflowThreatList);
      
      dataflowThreatList.forEach(threat => {
        threat.id = uuidv4();
        threat.dataflowId = dataflow.id;
        threat.dataflowName = dataflow.name;
        threat.dataflowType = dataflow.type;
        threats.push(threat);
        riskSummary[threat.severity.toLowerCase()]++;
      });
    });

    // Apply custom rules if provided
    if (options.customRules) {
      threats.forEach(threat => {
        const customMitigations = options.customRules[threat.id];
        if (customMitigations) {
          threat.mitigations = [...threat.mitigations, ...customMitigations];
        }
      });
    }

    // Sort by severity
    threats.sort((a, b) => {
      const severityOrder = { 'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3 };
      return severityOrder[a.severity] - severityOrder[b.severity];
    });

    return {
      id: uuidv4(),
      dfdId: dfd.id,
      dfdName: dfd.name,
      threats,
      totalThreats: threats.length,
      riskSummary,
      createdAt: new Date().toISOString(),
      owasp_mapped: true
    };
  },

  analyzeElement(element, dfd) {
    const threats = [];
    const patterns = threatLibrary.getThreatPatterns(element.type);

    patterns.forEach(pattern => {
      // Check if pattern matches element characteristics
      if (this.matchesElement(element, pattern)) {
        const threat = {
          title: pattern.title,
          description: pattern.description,
          category: pattern.category,
          stride: pattern.stride,
          severity: this.calculateSeverity(pattern, element),
          likelihood: 'Medium',
          impact: pattern.impact || 'High',
          mitigations: pattern.mitigations || [],
          references: pattern.references || [],
          owaspCategory: pattern.owaspCategory || 'A01:2021 – Broken Access Control'
        };
        threats.push(threat);
      }
    });

    // Add role-based threats
    if (element.isExternalEntity) {
      threats.push({
        title: 'Malicious External Actor',
        description: 'External entity may be compromised or act maliciously',
        category: 'Actor Threat',
        stride: ['Spoofing', 'Repudiation'],
        severity: 'High',
        likelihood: 'Medium',
        impact: 'High',
        mitigations: [
          'Implement authentication mechanisms',
          'Use digital signatures for verification',
          'Monitor for anomalous behavior',
          'Implement audit logging'
        ],
        owaspCategory: 'A07:2021 – Identification and Authentication Failures'
      });
    }

    if (element.isDatastore) {
      threats.push({
        title: 'Unauthorized Data Access',
        description: 'Sensitive data in datastore may be accessed without authorization',
        category: 'Information Disclosure',
        stride: ['Information Disclosure', 'Tampering'],
        severity: 'Critical',
        likelihood: 'High',
        impact: 'Critical',
        mitigations: [
          'Implement encryption at rest',
          'Use access control lists',
          'Implement database auditing',
          'Use data masking for sensitive fields',
          'Regular backup and recovery testing'
        ],
        owaspCategory: 'A01:2021 – Broken Access Control'
      });
    }

    if (element.isProcess) {
      threats.push({
        title: 'Privilege Escalation',
        description: 'Process may be exploited to escalate privileges',
        category: 'Authorization Bypass',
        stride: ['Elevation of Privilege'],
        severity: 'High',
        likelihood: 'Medium',
        impact: 'Critical',
        mitigations: [
          'Run with least privilege principle',
          'Input validation and sanitization',
          'Use security frameworks',
          'Implement RBAC',
          'Regular security testing'
        ],
        owaspCategory: 'A04:2021 – Insecure Design'
      });
    }

    return threats;
  },

  analyzeDataflow(dataflow, dfd) {
    const threats = [];
    const dataflowPatterns = threatLibrary.getThreatPatterns('dataflow');

    dataflowPatterns.forEach(pattern => {
      if (this.matchesDataflow(dataflow, pattern)) {
        const threat = {
          title: pattern.title,
          description: pattern.description,
          category: pattern.category,
          stride: pattern.stride,
          severity: this.calculateSeverityForDataflow(pattern, dataflow),
          likelihood: 'High',
          impact: pattern.impact || 'High',
          mitigations: pattern.mitigations || [],
          references: pattern.references || [],
          owaspCategory: pattern.owaspCategory || 'A02:2021 – Cryptographic Failures'
        };
        threats.push(threat);
      }
    });

    // Analyze based on dataflow characteristics
    if (dataflow.protocol && dataflow.protocol.toLowerCase() === 'http') {
      threats.push({
        title: 'Man-in-the-Middle Attack',
        description: 'Unencrypted HTTP dataflow is vulnerable to MITM attacks',
        category: 'Network Attack',
        stride: ['Tampering', 'Information Disclosure'],
        severity: 'Critical',
        likelihood: 'High',
        impact: 'Critical',
        mitigations: [
          'Use HTTPS/TLS encryption',
          'Implement certificate pinning',
          'Use HSTS headers',
          'Implement perfect forward secrecy',
          'Regular security updates'
        ],
        owaspCategory: 'A02:2021 – Cryptographic Failures'
      });
    }

    if (dataflow.hasSensitiveData) {
      threats.push({
        title: 'Data Exposure During Transit',
        description: 'Sensitive data may be exposed if not properly protected in transit',
        category: 'Data Protection',
        stride: ['Information Disclosure'],
        severity: 'Critical',
        likelihood: 'High',
        impact: 'Critical',
        mitigations: [
          'Encrypt data in transit (TLS 1.2+)',
          'Use strong encryption algorithms',
          'Implement key management',
          'Data classification policy',
          'Regular encryption audits'
        ],
        owaspCategory: 'A02:2021 – Cryptographic Failures'
      });
    }

    return threats;
  },

  matchesElement(element, pattern) {
    // Simple matching logic - can be enhanced
    if (!pattern.targets) return true;
    return pattern.targets.includes(element.type);
  },

  matchesDataflow(dataflow, pattern) {
    if (!pattern.appliesToDataflow) return false;
    if (pattern.protocols && !pattern.protocols.includes(dataflow.protocol)) return false;
    return true;
  },

  calculateSeverity(pattern, element) {
    // Calculate based on pattern and element characteristics
    const baseSeverity = pattern.severity || 'Medium';
    
    if (element.trustLevel === 'untrusted') {
      return 'Critical';
    } else if (element.trustLevel === 'partially-trusted') {
      return baseSeverity === 'Low' ? 'Medium' : baseSeverity;
    }
    
    return baseSeverity;
  },

  calculateSeverityForDataflow(pattern, dataflow) {
    let severity = pattern.severity || 'Medium';
    
    if (dataflow.hasSensitiveData) {
      severity = 'Critical';
    } else if (dataflow.isCrossNetwork) {
      severity = severity === 'Low' ? 'Medium' : 'High';
    }
    
    return severity;
  },

  generateReport(threatModel, dfd) {
    const report = {
      title: `Threat Model Report: ${dfd.name}`,
      description: dfd.description,
      generatedAt: new Date().toISOString(),
      executive_summary: {
        total_threats: threatModel.totalThreats,
        critical_threats: threatModel.riskSummary.critical,
        high_threats: threatModel.riskSummary.high,
        medium_threats: threatModel.riskSummary.medium,
        low_threats: threatModel.riskSummary.low,
        overall_risk: threatModel.riskSummary.critical > 0 ? 'Critical' : 
                     threatModel.riskSummary.high > 0 ? 'High' : 'Medium'
      },
      elements_analysis: [],
      dataflow_analysis: [],
      recommendations: [],
      stride_breakdown: this.breakdownBySTRIDE(threatModel.threats)
    };

    // Add element analysis
    dfd.elements.forEach(element => {
      const elementThreats = threatModel.threats.filter(t => t.elementId === element.id);
      if (elementThreats.length > 0) {
        report.elements_analysis.push({
          element_id: element.id,
          element_name: element.name,
          element_type: element.type,
          threat_count: elementThreats.length,
          threats: elementThreats
        });
      }
    });

    // Add dataflow analysis
    dfd.dataflows.forEach(dataflow => {
      const dataflowThreats = threatModel.threats.filter(t => t.dataflowId === dataflow.id);
      if (dataflowThreats.length > 0) {
        report.dataflow_analysis.push({
          dataflow_id: dataflow.id,
          dataflow_name: dataflow.name,
          from: dataflow.from,
          to: dataflow.to,
          threat_count: dataflowThreats.length,
          threats: dataflowThreats
        });
      }
    });

    // Generate recommendations
    report.recommendations = this.generateRecommendations(threatModel, dfd);

    return report;
  },

  breakdownBySTRIDE(threats) {
    const breakdown = {
      'Spoofing': [],
      'Tampering': [],
      'Repudiation': [],
      'Information Disclosure': [],
      'Denial of Service': [],
      'Elevation of Privilege': []
    };

    threats.forEach(threat => {
      if (threat.stride && Array.isArray(threat.stride)) {
        threat.stride.forEach(category => {
          if (breakdown[category]) {
            breakdown[category].push(threat);
          }
        });
      }
    });

    return Object.fromEntries(
      Object.entries(breakdown).filter(([_, threats]) => threats.length > 0)
    );
  },

  generateRecommendations(threatModel, dfd) {
    const recommendations = [];
    const criticalThreats = threatModel.threats.filter(t => t.severity === 'Critical');
    const highThreats = threatModel.threats.filter(t => t.severity === 'High');

    if (criticalThreats.length > 0) {
      recommendations.push({
        priority: 'Critical',
        action: `Address ${criticalThreats.length} critical threats immediately`,
        details: 'Critical threats pose immediate risk to system security and data integrity',
        timeline: 'Immediate (within 24-48 hours)'
      });
    }

    if (highThreats.length > 0) {
      recommendations.push({
        priority: 'High',
        action: `Implement mitigations for ${highThreats.length} high-severity threats`,
        details: 'High threats should be addressed in the next development cycle',
        timeline: 'Within 1-2 sprints'
      });
    }

    recommendations.push({
      priority: 'Medium',
      action: 'Implement security best practices',
      details: 'Follow OWASP top 10 principles and secure coding standards',
      timeline: 'Ongoing'
    });

    recommendations.push({
      priority: 'Low',
      action: 'Conduct security awareness training',
      details: 'Train team on threat modeling and secure development',
      timeline: 'Quarterly'
    });

    return recommendations;
  }
};

export default threatGenerator;
