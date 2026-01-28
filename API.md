# API Documentation

## Base URL

```
http://localhost:3000/api
```

## Authentication

Currently, the API does not require authentication. In production, implement JWT or OAuth 2.0.

## Response Format

All responses are in JSON format.

### Success Response

```json
{
  "success": true,
  "data": { ... },
  "timestamp": "2024-01-28T14:30:00Z"
}
```

### Error Response

```json
{
  "success": false,
  "error": "Error message",
  "timestamp": "2024-01-28T14:30:00Z"
}
```

## Endpoints

### Health Check

**GET** `/api/health`

Check if the API is running.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-28T14:30:00Z"
}
```

---

### Threat Library

#### Get Library Metadata

**GET** `/api/threats/library`

Retrieve metadata about the threat pattern library.

**Response:**
```json
{
  "version": "1.0.0",
  "source": "OWASP Threat Model Library",
  "categories": [
    "Actor Threat",
    "Input Validation",
    "Authorization",
    "Authentication",
    "Business Logic",
    "Information Disclosure",
    "Data Integrity",
    "Availability",
    "Injection",
    "Network Attack",
    "Third-Party Risk"
  ],
  "totalPatterns": 20,
  "strideCoverage": [
    "Spoofing",
    "Tampering",
    "Repudiation",
    "Information Disclosure",
    "Denial of Service",
    "Elevation of Privilege"
  ],
  "supportedElementTypes": [
    "actor",
    "process",
    "datastore",
    "external_entity"
  ]
}
```

---

#### Get Threat Patterns by Type

**GET** `/api/threats/patterns/:type`

Retrieve threat patterns for a specific element type.

**Parameters:**
- `type` (string): Element type - `process`, `datastore`, `actor`, `external_entity`, `dataflow`

**Response:**
```json
[
  {
    "id": "PROC01",
    "title": "Input Validation Bypass",
    "description": "Process may not properly validate input, leading to injection attacks",
    "category": "Input Validation",
    "stride": ["Tampering"],
    "severity": "Critical",
    "impact": "Critical",
    "mitigations": [
      "Implement strict input validation",
      "Use parameterized queries",
      "Whitelist acceptable input patterns"
    ],
    "owaspCategory": "A03:2021 – Injection"
  }
]
```

---

### DFD Operations

#### Validate DFD

**POST** `/api/dfd/validate`

Validate the structure and security configuration of a DFD.

**Request Body:**
```json
{
  "dfd": {
    "id": "dfd_123",
    "name": "My System",
    "elements": [
      {
        "id": "elem_1",
        "name": "Web Server",
        "type": "process"
      }
    ],
    "dataflows": [
      {
        "id": "df_1",
        "name": "User Request",
        "from": "elem_1",
        "to": "elem_2"
      }
    ]
  }
}
```

**Response:**
```json
{
  "valid": true,
  "errors": [],
  "warnings": [
    "Dataflow 'User Request' carries sensitive data but is not encrypted"
  ],
  "elementCount": 5,
  "dataflowCount": 8,
  "trustBoundaryCount": 2
}
```

---

### Threat Generation

#### Generate Threat Model

**POST** `/api/threats/generate`

Generate a complete threat model from a DFD.

**Request Body:**
```json
{
  "dfd": {
    "id": "dfd_123",
    "name": "E-Commerce Platform",
    "description": "Online shopping system",
    "elements": [
      {
        "id": "elem_user",
        "name": "Customer",
        "type": "actor",
        "trustLevel": "untrusted"
      },
      {
        "id": "elem_web",
        "name": "Web Server",
        "type": "process",
        "trustLevel": "trusted"
      },
      {
        "id": "elem_db",
        "name": "Database",
        "type": "datastore",
        "trustLevel": "trusted"
      }
    ],
    "dataflows": [
      {
        "id": "df_1",
        "name": "User Login",
        "from": "elem_user",
        "to": "elem_web",
        "protocol": "HTTPS",
        "hasSensitiveData": true,
        "isEncrypted": true
      },
      {
        "id": "df_2",
        "name": "Query Database",
        "from": "elem_web",
        "to": "elem_db",
        "protocol": "TCP",
        "hasSensitiveData": true,
        "isEncrypted": true
      }
    ]
  },
  "options": {
    "customRules": {}
  }
}
```

**Response:**
```json
{
  "success": true,
  "threatModel": {
    "id": "tm_abc123",
    "dfdId": "dfd_123",
    "dfdName": "E-Commerce Platform",
    "threats": [
      {
        "id": "threat_001",
        "title": "Man-in-the-Middle Attack",
        "description": "Unencrypted dataflow is vulnerable to interception",
        "category": "Network Attack",
        "stride": ["Tampering", "Information Disclosure"],
        "severity": "Critical",
        "likelihood": "High",
        "impact": "Critical",
        "elementId": "elem_web",
        "elementName": "Web Server",
        "mitigations": [
          "Use TLS 1.2+ for all communications",
          "Implement certificate pinning"
        ],
        "owaspCategory": "A02:2021 – Cryptographic Failures"
      }
    ],
    "totalThreats": 15,
    "riskSummary": {
      "critical": 3,
      "high": 5,
      "medium": 5,
      "low": 2
    },
    "createdAt": "2024-01-28T14:30:00Z"
  },
  "summary": {
    "totalElements": 3,
    "totalDataflows": 2,
    "threatsIdentified": 15,
    "riskLevels": {
      "critical": 3,
      "high": 5,
      "medium": 5,
      "low": 2
    }
  }
}
```

**Error Response (Invalid DFD):**
```json
{
  "success": false,
  "errors": [
    "DFD name is required",
    "DFD must have at least one element",
    "Dataflow 'df_1': destination element 'elem_unknown' not found"
  ]
}
```

---

#### Generate Threat Analysis Report

**POST** `/api/reports/threat-analysis`

Generate a detailed threat analysis report.

**Request Body:** (Same as threat generation)

**Response:**
```json
{
  "success": true,
  "report": {
    "title": "Threat Model Report: E-Commerce Platform",
    "description": "Online shopping system",
    "generatedAt": "2024-01-28T14:30:00Z",
    "executive_summary": {
      "total_threats": 15,
      "critical_threats": 3,
      "high_threats": 5,
      "medium_threats": 5,
      "low_threats": 2,
      "overall_risk": "Critical"
    },
    "elements_analysis": [
      {
        "element_id": "elem_web",
        "element_name": "Web Server",
        "element_type": "process",
        "threat_count": 5,
        "threats": [ ... ]
      }
    ],
    "stride_breakdown": {
      "Tampering": [ ... ],
      "Information Disclosure": [ ... ]
    },
    "recommendations": [
      {
        "priority": "Critical",
        "action": "Address 3 critical threats immediately",
        "details": "Critical threats pose immediate risk to system security",
        "timeline": "Immediate (within 24-48 hours)"
      }
    ]
  }
}
```

---

### Export Operations

#### Export as JSON

**POST** `/api/export/json`

Export threat model as OWASP-compatible JSON.

**Request Body:**
```json
{
  "dfd": { ... },
  "threatModel": { ... }
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "version": "1.0.0",
    "schema": "https://github.com/OWASP/www-project-threat-model-library/blob/v1.0.0/threat-model.schema.json",
    "metadata": {
      "created": "2024-01-28T14:30:00Z",
      "title": "E-Commerce Platform",
      "description": "Online shopping system"
    },
    "elements": [ ... ],
    "dataflows": [ ... ],
    "threatModel": { ... }
  }
}
```

---

## Error Codes

| Code | Message | Description |
|------|---------|-------------|
| 400 | Bad Request | Invalid request parameters or body |
| 404 | Not Found | Endpoint or resource not found |
| 500 | Internal Server Error | Server processing error |

---

## Rate Limiting

Currently not implemented. Recommended for production:
- 100 requests per minute for threat generation
- 1000 requests per minute for library queries

---

## CORS

CORS is enabled for all origins. In production, restrict to specific domains:

```javascript
const cors = require('cors');
app.use(cors({
  origin: ['https://yourdomain.com', 'https://app.yourdomain.com']
}));
```

---

## Best Practices

1. Always validate DFD before generating threats
2. Include complete dataflow information (protocol, encryption status, sensitive data flags)
3. Define trust boundaries for accurate threat analysis
4. Review and validate all generated threats
5. Export reports for documentation and tracking
6. Keep threat library updated with latest OWASP patterns

---

## Support

For API issues or feature requests, open an issue on GitHub.
