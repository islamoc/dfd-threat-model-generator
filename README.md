# 🔐 DFD Threat Model Generator

**AI-powered threat model generation from Data Flow Diagrams using OWASP Threat Model Library**

A comprehensive tool that automatically analyzes Data Flow Diagrams (DFDs) and generates detailed threat models using OWASP threat patterns and STRIDE methodology.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GitHub Repo](https://img.shields.io/badge/GitHub-dfd--threat--model--generator-blue.svg)](https://github.com/islamoc/dfd-threat-model-generator)

## ✨ Features

- **Interactive DFD Builder**: Visual interface to define your system architecture
- **Automated Threat Detection**: Uses OWASP threat patterns to identify vulnerabilities
- **STRIDE Analysis**: Comprehensive security threat categorization
- **Multiple Export Formats**: JSON and CSV exports for integration with other tools
- **Detailed Reports**: Executive summaries and mitigation recommendations
- **Real-time Validation**: DFD validation with security warnings
- **Severity Classification**: Threats categorized by risk levels (Critical, High, Medium, Low)

## 🚀 Quick Start

### Prerequisites

- Node.js 16+
- npm or yarn

### Installation

```bash
# Clone the repository
git clone https://github.com/islamoc/dfd-threat-model-generator.git
cd dfd-threat-model-generator

# Install dependencies
npm install

# Start the server
npm start
```

The application will be available at `http://localhost:3000`

## 📖 Usage

### 1. Define Your DFD

- Enter your project name and description
- Add system elements (Actors, Processes, Data Stores, External Entities)
- Define data flows between elements
- Mark flows carrying sensitive data
- Specify communication protocols

### 2. Generate Threat Model

- Click "Generate Threat Model" button
- The system analyzes your DFD against OWASP threat patterns
- Threats are automatically identified and categorized

### 3. Review Results

- **All Threats Tab**: Complete list of identified threats
- **By Severity Tab**: Threats grouped by risk level
- **By STRIDE Tab**: Threats categorized by STRIDE classification
- **Report Tab**: Executive summary with recommendations

### 4. Export & Share

- Export threat model as JSON for tool integration
- Export as CSV for spreadsheet analysis
- Print detailed reports

## 🏗️ Architecture

### Backend (Node.js/Express)

```
server.js              # Express API server
src/
  ├── threatGenerator.js    # Threat identification and analysis
  ├── threatLibrary.js      # OWASP threat patterns database
  └── dfdValidator.js       # DFD validation logic
```

### Frontend (Vanilla JavaScript)

```
public/
  ├── index.html      # UI interface
  └── app.js          # Frontend logic
```

## 📊 Threat Model Data Structure

### DFD Object

```json
{
  "id": "dfd_123",
  "name": "E-Commerce Platform",
  "description": "Online shopping system",
  "elements": [
    {
      "id": "elem_1",
      "name": "Web Server",
      "type": "process",
      "trustLevel": "trusted"
    }
  ],
  "dataflows": [
    {
      "id": "df_1",
      "name": "User Login",
      "from": "elem_user",
      "to": "elem_server",
      "protocol": "HTTPS",
      "hasSensitiveData": true,
      "isEncrypted": true
    }
  ]
}
```

## 🎯 STRIDE Categories

Threat Model uses STRIDE for threat categorization:

- **S**poofing: Identity spoofing attacks
- **T**ampering: Data modification attacks
- **R**epudiation: Denial of actions
- **I**nformation Disclosure: Data exposure
- **D**enial of Service: System unavailability
- **E**levation of Privilege: Unauthorized access escalation

## 📚 OWASP Integration

The tool uses threat patterns from:

- [OWASP Threat Model Library](https://github.com/OWASP/www-project-threat-model-library)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

## 🔌 API Endpoints

### Health Check
```
GET /api/health
```

### Threat Library
```
GET /api/threats/library           # Get library metadata
GET /api/threats/patterns/:type    # Get patterns by element type
```

### DFD Operations
```
POST /api/dfd/validate             # Validate DFD structure
```

### Threat Generation
```
POST /api/threats/generate         # Generate threat model from DFD
POST /api/reports/threat-analysis  # Generate detailed report
POST /api/export/json              # Export threat model
```

## 🛡️ Security Features

- **Input Validation**: All DFD inputs validated against schema
- **CORS Protection**: Cross-Origin Resource Sharing configured
- **Threat Mitigation**: Recommended mitigations for each threat
- **Trust Boundaries**: Support for defining security boundaries
- **Encryption Detection**: Identifies unencrypted data flows

## 💡 Example Threat Detection

The system identifies threats such as:

- **Man-in-the-Middle Attacks**: On unencrypted HTTP flows
- **SQL Injection**: In database interactions
- **Privilege Escalation**: In process-based components
- **Data Exposure**: On sensitive unencrypted dataflows
- **Broken Authentication**: In actor interactions
- **Business Logic Bypass**: In process components

## 📋 Supported Element Types

- **Actor/User**: External users or actors
- **Process**: Business logic components
- **Data Store**: Databases or file systems
- **External Entity**: Third-party systems

## 🧪 Testing

```bash
# Run tests (when implemented)
npm test
```

## 📦 Dependencies

- **express**: Web framework
- **cors**: Cross-origin resource sharing
- **uuid**: Unique ID generation
- **jsonschema**: Schema validation

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 🐛 Bug Reports

Found a bug? Please open an issue with:
- Description of the problem
- Steps to reproduce
- Expected vs actual behavior
- System information

## 📄 License

MIT License - see LICENSE file for details

## 👨‍💼 Author

**Mennouchi Islam Azeddine**
- GitHub: [@islamoc](https://github.com/islamoc)
- Email: azeddine.mennouchi@owasp.org
- LinkedIn: [Profile](https://www.linkedin.com/in/azeddine-mennouchi/)

## 🙏 Acknowledgments

- [OWASP Foundation](https://owasp.org) for threat modeling resources
- [OWASP Threat Model Library](https://github.com/OWASP/www-project-threat-model-library) for threat patterns
- [Microsoft Threat Modeling Tool](https://microsoft.com/threat-modeling-tool) for methodology inspiration

## 📞 Support

- **Issues**: GitHub Issues
- **Discussions**: GitHub Discussions
- **Documentation**: See `/docs` folder

## 🗺️ Roadmap

- [ ] Integration with Threat Dragon
- [ ] AI-powered threat suggestions
- [ ] Custom threat library management
- [ ] Real-time collaboration
- [ ] Risk scoring engine
- [ ] Compliance mapping (GDPR, HIPAA, etc.)
- [ ] Docker containerization
- [ ] GraphQL API

## 📊 Statistics

- **Threat Patterns**: 20+ OWASP patterns
- **Element Types**: 6 supported types
- **Export Formats**: JSON, CSV, PDF (planned)
- **Risk Levels**: 4 severity classifications

---

**Made with ❤️ for the security community**
