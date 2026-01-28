// DFD Validator - Validates Data Flow Diagram structure and completeness

const dfdValidator = {
  schema: {
    type: 'object',
    required: ['id', 'name', 'elements', 'dataflows'],
    properties: {
      id: { type: 'string' },
      name: { type: 'string' },
      description: { type: 'string' },
      elements: {
        type: 'array',
        items: {
          type: 'object',
          required: ['id', 'name', 'type'],
          properties: {
            id: { type: 'string' },
            name: { type: 'string' },
            type: {
              type: 'string',
              enum: ['actor', 'process', 'datastore', 'external_entity', 'user', 'database']
            },
            description: { type: 'string' },
            isExternalEntity: { type: 'boolean' },
            isDatastore: { type: 'boolean' },
            isProcess: { type: 'boolean' },
            trustLevel: { 
              type: 'string',
              enum: ['trusted', 'partially-trusted', 'untrusted']
            },
            position: { type: 'object' },
            properties: { type: 'object' }
          }
        }
      },
      dataflows: {
        type: 'array',
        items: {
          type: 'object',
          required: ['id', 'from', 'to', 'name'],
          properties: {
            id: { type: 'string' },
            name: { type: 'string' },
            from: { type: 'string' },
            to: { type: 'string' },
            description: { type: 'string' },
            data: { type: 'string' },
            protocol: { type: 'string' },
            port: { type: ['number', 'string'] },
            hasSensitiveData: { type: 'boolean' },
            isCrossNetwork: { type: 'boolean' },
            isEncrypted: { type: 'boolean' },
            authentication: { type: 'string' },
            type: { type: 'string' }
          }
        }
      },
      trustBoundaries: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            id: { type: 'string' },
            name: { type: 'string' },
            elements: {
              type: 'array',
              items: { type: 'string' }
            }
          }
        }
      }
    }
  },

  validate(dfd) {
    const errors = [];
    const warnings = [];

    // Check required fields
    if (!dfd) {
      return {
        valid: false,
        errors: ['DFD object is required']
      };
    }

    if (!dfd.id) errors.push('DFD ID is required');
    if (!dfd.name) errors.push('DFD name is required');
    if (!Array.isArray(dfd.elements) || dfd.elements.length === 0) {
      errors.push('DFD must have at least one element');
    }
    if (!Array.isArray(dfd.dataflows)) {
      errors.push('DFD must have dataflows array');
    }

    // Validate elements
    if (Array.isArray(dfd.elements)) {
      const elementIds = new Set();
      const validTypes = ['actor', 'process', 'datastore', 'external_entity', 'user', 'database'];

      dfd.elements.forEach((element, index) => {
        // Check required element fields
        if (!element.id) errors.push(`Element ${index} missing required field: id`);
        if (!element.name) errors.push(`Element ${index} missing required field: name`);
        if (!element.type) {
          errors.push(`Element ${index} missing required field: type`);
        } else if (!validTypes.includes(element.type)) {
          errors.push(`Element ${index} has invalid type: ${element.type}`);
        }

        // Check for duplicate IDs
        if (element.id && elementIds.has(element.id)) {
          errors.push(`Duplicate element ID: ${element.id}`);
        }
        if (element.id) elementIds.add(element.id);

        // Type-specific validation
        if (element.type === 'datastore' || element.type === 'database') {
          element.isDatastore = true;
          if (!element.description) {
            warnings.push(`Datastore '${element.name}' should have description`);
          }
        }

        if (element.type === 'external_entity' || element.type === 'actor' || element.type === 'user') {
          element.isExternalEntity = true;
        }

        if (element.type === 'process') {
          element.isProcess = true;
        }
      });
    }

    // Validate dataflows
    if (Array.isArray(dfd.dataflows)) {
      const dataflowIds = new Set();
      const elementIds = new Set(dfd.elements?.map(e => e.id) || []);

      dfd.dataflows.forEach((dataflow, index) => {
        // Check required dataflow fields
        if (!dataflow.id) errors.push(`Dataflow ${index} missing required field: id`);
        if (!dataflow.from) errors.push(`Dataflow ${index} missing required field: from`);
        if (!dataflow.to) errors.push(`Dataflow ${index} missing required field: to`);
        if (!dataflow.name) errors.push(`Dataflow ${index} missing required field: name`);

        // Check for duplicate IDs
        if (dataflow.id && dataflowIds.has(dataflow.id)) {
          errors.push(`Duplicate dataflow ID: ${dataflow.id}`);
        }
        if (dataflow.id) dataflowIds.add(dataflow.id);

        // Check if endpoints exist
        if (dataflow.from && !elementIds.has(dataflow.from)) {
          errors.push(`Dataflow '${dataflow.name}': source element '${dataflow.from}' not found`);
        }
        if (dataflow.to && !elementIds.has(dataflow.to)) {
          errors.push(`Dataflow '${dataflow.name}': destination element '${dataflow.to}' not found`);
        }

        // Security warnings
        if (dataflow.hasSensitiveData && !dataflow.isEncrypted) {
          warnings.push(`Dataflow '${dataflow.name}' carries sensitive data but is not encrypted`);
        }

        if (dataflow.protocol && ['http', 'ftp', 'telnet', 'smtp'].includes(dataflow.protocol?.toLowerCase())) {
          warnings.push(`Dataflow '${dataflow.name}' uses unencrypted protocol: ${dataflow.protocol}`);
        }

        if (!dataflow.authentication && dataflow.isCrossNetwork) {
          warnings.push(`Dataflow '${dataflow.name}' crosses network boundary but lacks authentication`);
        }
      });
    }

    // Check for orphaned elements
    if (Array.isArray(dfd.elements) && Array.isArray(dfd.dataflows)) {
      const connectedElements = new Set();
      
      dfd.dataflows.forEach(df => {
        connectedElements.add(df.from);
        connectedElements.add(df.to);
      });

      dfd.elements.forEach(element => {
        if (!connectedElements.has(element.id)) {
          warnings.push(`Element '${element.name}' is not connected to any dataflow`);
        }
      });
    }

    // Check for trust boundaries
    if (!Array.isArray(dfd.trustBoundaries) || dfd.trustBoundaries.length === 0) {
      warnings.push('No trust boundaries defined. Consider adding trust boundaries to your DFD');
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings,
      elementCount: dfd.elements?.length || 0,
      dataflowCount: dfd.dataflows?.length || 0,
      trustBoundaryCount: dfd.trustBoundaries?.length || 0
    };
  },

  validateSecurity(dfd) {
    const securityIssues = [];

    // Check for unencrypted dataflows carrying sensitive data
    if (Array.isArray(dfd.dataflows)) {
      dfd.dataflows.forEach(dataflow => {
        if (dataflow.hasSensitiveData && !dataflow.isEncrypted) {
          securityIssues.push({
            severity: 'high',
            message: `Sensitive data in unencrypted dataflow: ${dataflow.name}`,
            recommendation: 'Enable encryption (TLS 1.2+) for this dataflow'
          });
        }

        if (dataflow.protocol?.toLowerCase() === 'http') {
          securityIssues.push({
            severity: 'high',
            message: `Insecure protocol HTTP used in dataflow: ${dataflow.name}`,
            recommendation: 'Use HTTPS instead of HTTP'
          });
        }
      });
    }

    // Check for datastores without trust levels
    if (Array.isArray(dfd.elements)) {
      dfd.elements.forEach(element => {
        if (element.isDatastore && !element.trustLevel) {
          securityIssues.push({
            severity: 'medium',
            message: `Datastore '${element.name}' has no trust level defined`,
            recommendation: 'Define appropriate trust level (trusted/partially-trusted/untrusted)'
          });
        }

        if (element.isExternalEntity && element.trustLevel === 'trusted') {
          securityIssues.push({
            severity: 'medium',
            message: `External entity '${element.name}' marked as trusted`,
            recommendation: 'External entities should be marked as untrusted by default'
          });
        }
      });
    }

    return {
      hasSecurityIssues: securityIssues.length > 0,
      issues: securityIssues
    };
  },

  getSummary(dfd) {
    const validation = this.validate(dfd);
    const securityValidation = this.validateSecurity(dfd);

    return {
      ...validation,
      security: securityValidation,
      completeness: {
        hasDescription: !!dfd.description,
        hasTrustBoundaries: Array.isArray(dfd.trustBoundaries) && dfd.trustBoundaries.length > 0,
        allElementsConnected: validation.warnings.filter(w => w.includes('not connected')).length === 0,
        allDataflowsSecured: securityValidation.issues.length === 0
      }
    };
  }
};

export default dfdValidator;
