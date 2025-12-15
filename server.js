// // server.js
// const express = require('express');
// const cors = require('cors');
// const Anthropic = require('@anthropic-ai/sdk');

// const app = express();

// // Increase timeout to 5 minutes
// app.use((req, res, next) => {
//   req.setTimeout(300000); // 5 minutes
//   res.setTimeout(300000);
//   next();
// });

// app.use(cors());
// app.use(express.json({ limit: '10mb' }));

// // Health check
// app.get('/', (req, res) => {
//   res.json({ 
//     status: 'Server is running', 
//     timestamp: new Date().toISOString() 
//   });
// });

// app.post('/api/analyze', async (req, res) => {
//   // Set longer timeout for this specific route
//   req.setTimeout(300000);
//   res.setTimeout(300000);
  
//   try {
//     console.log('Received analysis request');
    
//     const { apiKey, imageBase64, mediaType } = req.body;
    
//     if (!apiKey || !imageBase64 || !mediaType) {
//       return res.status(400).json({ 
//         error: 'Missing required fields: apiKey, imageBase64, or mediaType' 
//       });
//     }
    
//     console.log('Creating Anthropic client...');
//     const anthropic = new Anthropic({ apiKey });
    
//     // Check if it's a PDF
//     const isPDF = mediaType === 'application/pdf';
//     console.log(`Processing ${isPDF ? 'PDF' : 'image'}...`);
    
//     console.log('Sending request to Claude API...');
//     const message = await anthropic.messages.create({
//       model: 'claude-sonnet-4-20250514',
//       max_tokens: 4096,
//       messages: [
//         {
//           role: 'user',
//           content: [
//             {
//               type: isPDF ? 'document' : 'image',
//               source: { 
//                 type: 'base64', 
//                 media_type: mediaType, 
//                 data: imageBase64 
//               }
//             },
//             { 
//               type: 'text', 
//               text: `You are an expert cybersecurity architect and threat modeling specialist. Analyze this architecture diagram in detail.

// CRITICAL: Format your response EXACTLY as shown below with clear sections and structured data:

// # 1. ARCHITECTURE OVERVIEW

// Provide a detailed overview of the architecture including:
// - Overall architecture pattern
// - Data flow description
// - Trust boundaries and security zones
// - Network topology

// # 2. IDENTIFIED COMPONENTS

// List each component in this format:
// - **[Component Name]**
//   Type: [Database/Web Server/API/Load Balancer/etc.]
//   Exposure: [External/Internal/Isolated]
//   Description: [Brief description of role and data handled]

// # 3. THREAT ANALYSIS

// For each threat, use this EXACT format:
// - **Threat ID: T-001**
//   Attack Vector: [Detailed description of how attack is executed]
//   Impact: [What could be compromised - Confidentiality/Integrity/Availability]
//   Likelihood: [High/Medium/Low]
//   Risk Score: [Critical/High/Medium/Low]

// - **Threat ID: T-002**
//   Attack Vector: [Description]
//   Impact: [Description]
//   Likelihood: [High/Medium/Low]
//   Risk Score: [Critical/High/Medium/Low]

// [Continue for all threats - identify at least 5-8 major threats]

// # 4. IDENTIFIED VULNERABILITIES & MISCONFIGURATIONS

// List each vulnerability:
// - **[Vulnerability Name]**: [Detailed description of the security issue and potential impact]

// # 5. MITIGATIONS & RECOMMENDATIONS

// **Quick Wins (Immediate Actions):**
// - [Specific actionable mitigation]: [Implementation details]

// **Short-term Improvements (1-3 months):**
// - [Specific improvement]: [Implementation details]

// **Long-term Strategic Changes:**
// - [Strategic change]: [Implementation details]

// # 6. COMPLIANCE CONSIDERATIONS

// - Relevant frameworks: [NIST, ISO 27001, SOC 2, etc.]
// - Compliance gaps identified
// - Recommended compliance actions

// Apply STRIDE framework (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) throughout the analysis. Be specific, actionable, and thorough.`
//             }
//           ]
//         }
//       ]
//     });
    
//     console.log('Received response from Claude API');
//     res.json({ content: message.content });
    
//   } catch (error) {
//     console.error('Error during analysis:', error.message);
//     console.error('Full error:', error);
//     res.status(500).json({ 
//       error: error.message,
//       details: error.error?.message || 'Unknown error'
//     });
//   }
// });

// const PORT = process.env.PORT || 3000;
// const server = app.listen(PORT, () => {
//   console.log(`Server running on port ${PORT}`);
// });

// // Increase server timeout
// server.timeout = 300000; // 5 minutes

// server.js
// const express = require('express');
// const cors = require('cors');
// const Anthropic = require('@anthropic-ai/sdk');

// const app = express();
// app.use(cors());
// app.use(express.json({ limit: '10mb' }));

// // Health check endpoint
// app.get('/', (req, res) => {
//   res.json({ 
//     status: 'Server is running', 
//     timestamp: new Date().toISOString() 
//   });
// });

// // Methodology-specific prompts
// const getMethodologyPrompt = (methodology) => {
//   const prompts = {
//     'STRIDE': `Apply the STRIDE framework (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) throughout the analysis. Focus on identifying threats in each STRIDE category.`,
    
//     'PASTA': `Use the PASTA (Process for Attack Simulation and Threat Analysis) methodology with these stages:
// 1. Define business objectives
// 2. Define technical scope
// 3. Application decomposition
// 4. Threat analysis
// 5. Vulnerability and weakness analysis
// 6. Attack modeling
// 7. Risk and impact analysis`,
    
//     'VAST': `Apply VAST (Visual, Agile, and Simple Threat modeling) methodology:
// - Create visual threat scenarios
// - Focus on both application and operational threats
// - Provide actionable, developer-friendly recommendations
// - Consider both process flow and architectural risks`,
    
//     'OCTAVE': `Use OCTAVE (Operationally Critical Threat, Asset, and Vulnerability Evaluation):
// - Identify critical assets
// - Profile threats to those assets
// - Examine vulnerabilities and evaluate risks
// - Develop protection strategy and mitigation plans`,
    
//     'MITRE_ATT&CK': `Apply the MITRE ATT&CK framework:
// - Map potential attack tactics and techniques
// - Identify specific TTPs (Tactics, Techniques, and Procedures)
// - Reference relevant ATT&CK technique IDs (e.g., T1078, T1190)
// - Focus on realistic attack paths and adversary behaviors`,
    
//     'DREAD': `Use DREAD scoring methodology:
// - Damage: How bad would an attack be?
// - Reproducibility: How easy is it to reproduce?
// - Exploitability: How much work is needed to launch?
// - Affected users: How many people will be impacted?
// - Discoverability: How easy is it to discover?
// Provide DREAD scores (1-10) for each threat.`,
    
//     'CVSS': `Apply CVSS (Common Vulnerability Scoring System) v3.1:
// - Provide Base Score metrics (Attack Vector, Attack Complexity, Privileges Required, User Interaction, Scope, CIA Impact)
// - Calculate CVSS scores for identified vulnerabilities
// - Include both Base Score and Environmental Score where applicable`,
    
//     'OWASP': `Apply OWASP Top 10 and ASVS (Application Security Verification Standard):
// - Map threats to OWASP Top 10 categories
// - Apply ASVS verification levels
// - Focus on web application security risks
// - Include specific OWASP recommendations`,
    
//     'NIST_RMF': `Use NIST Risk Management Framework (RMF):
// - Categorize information system
// - Select appropriate security controls
// - Implement security controls
// - Assess control effectiveness
// - Authorize system operation
// - Monitor security controls continuously`,
    
//     'COMBINED': `Apply a combined approach using both STRIDE and MITRE ATT&CK:
// - Use STRIDE categories for threat identification
// - Map threats to MITRE ATT&CK tactics and techniques
// - Provide ATT&CK technique IDs for each threat
// - Create comprehensive coverage of both frameworks`
//   };
  
//   return prompts[methodology] || prompts['STRIDE'];
// };

// app.post('/api/analyze', async (req, res) => {
//   try {
//     console.log('Received analysis request');
    
//     const { apiKey, imageBase64, mediaType, methodology = 'STRIDE' } = req.body;
    
//     if (!apiKey || !imageBase64 || !mediaType) {
//       return res.status(400).json({ 
//         error: 'Missing required fields: apiKey, imageBase64, or mediaType' 
//       });
//     }
    
//     console.log(`Using ${methodology} methodology`);
//     const anthropic = new Anthropic({ apiKey });
//     const isPDF = mediaType === 'application/pdf';
    
//     const methodologyPrompt = getMethodologyPrompt(methodology);
    
//     const message = await anthropic.messages.create({
//       model: 'claude-sonnet-4-20250514',
//       max_tokens: 4096,
//       messages: [
//         {
//           role: 'user',
//           content: [
//             {
//               type: isPDF ? 'document' : 'image',
//               source: { 
//                 type: 'base64', 
//                 media_type: mediaType, 
//                 data: imageBase64 
//               }
//             },
//             { 
//               type: 'text', 
//               text: `You are an expert cybersecurity architect and threat modeling specialist. Analyze this architecture diagram in detail using the ${methodology} methodology.

// CRITICAL: Format your response EXACTLY as shown below with clear sections and structured data:

// # 1. ARCHITECTURE OVERVIEW

// Provide a detailed overview of the architecture including:
// - Overall architecture pattern
// - Data flow description
// - Trust boundaries and security zones
// - Network topology

// # 2. IDENTIFIED COMPONENTS

// List each component in this format:
// - **[Component Name]**
//   Type: [Database/Web Server/API/Load Balancer/etc.]
//   Exposure: [External/Internal/Isolated]
//   Description: [Brief description of role and data handled]

// # 3. THREAT ANALYSIS (${methodology} Framework)

// For each threat, use this EXACT format:
// - **Threat ID: T-001**
//   Attack Vector: [Detailed description of how attack is executed]
//   Impact: [What could be compromised - Confidentiality/Integrity/Availability]
//   Likelihood: [High/Medium/Low]
//   Risk Score: [Critical/High/Medium/Low]
//   ${methodology === 'MITRE_ATT&CK' || methodology === 'COMBINED' ? 'MITRE ATT&CK Technique: [T1234 - Technique Name]' : ''}
//   ${methodology === 'DREAD' ? 'DREAD Score: [D:X/R:X/E:X/A:X/D:X = Total]' : ''}

// [Continue for all threats - identify at least 5-8 major threats]

// # 4. IDENTIFIED VULNERABILITIES & MISCONFIGURATIONS

// List each vulnerability:
// - **[Vulnerability Name]**: [Detailed description of the security issue and potential impact]

// # 5. MITIGATIONS & RECOMMENDATIONS

// **Quick Wins (Immediate Actions):**
// - [Specific actionable mitigation]: [Implementation details]

// **Short-term Improvements (1-3 months):**
// - [Specific improvement]: [Implementation details]

// **Long-term Strategic Changes:**
// - [Strategic change]: [Implementation details]

// # 6. COMPLIANCE CONSIDERATIONS

// - Relevant frameworks: [NIST, ISO 27001, SOC 2, etc.]
// - Compliance gaps identified
// - Recommended compliance actions

// ${methodologyPrompt}

// Be specific, actionable, and thorough in your analysis.`
//             }
//           ]
//         }
//       ]
//     });
    
//     console.log('Analysis complete');
//     res.json({ content: message.content });
    
//   } catch (error) {
//     console.error('Error during analysis:', error.message);
//     res.status(500).json({ 
//       error: error.message,
//       details: error.error?.message || 'Unknown error'
//     });
//   }
// });

// const PORT = process.env.PORT || 3000;
// app.listen(PORT, () => {
//   console.log(`Server running on port ${PORT}`);
// });


// server.js
const express = require('express');
const cors = require('cors');
const Anthropic = require('@anthropic-ai/sdk');

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// COMPLETE threat scope from your CSV - ALL THREATS INCLUDED
const THREAT_SCOPE = [
  {
    id: 'T-001',
    name: 'SQL Injection',
    category: 'Application Security',
    risk: 'Critical',
    description: 'Attacker injects malicious SQL queries through input fields',
    remediation: 'Use parameterized queries, input validation, ORM frameworks, principle of least privilege',
    detection: 'WAF logs, database query monitoring, SAST tools',
    reference: 'OWASP A03:2021, CWE-89'
  },
  {
    id: 'T-002',
    name: 'Cross-Site Scripting (XSS)',
    category: 'Application Security',
    risk: 'High',
    description: 'Injection of malicious scripts into web pages viewed by users',
    remediation: 'Content Security Policy, output encoding, input sanitization, HTTP-only cookies',
    detection: 'WAF, browser security tools, DAST scanning',
    reference: 'OWASP A03:2021, CWE-79'
  },
  {
    id: 'T-003',
    name: 'Cross-Site Request Forgery (CSRF)',
    category: 'Application Security',
    risk: 'High',
    description: 'Unauthorized commands transmitted from authenticated user',
    remediation: 'Anti-CSRF tokens, SameSite cookies, verify origin headers',
    detection: 'Session monitoring, request pattern analysis',
    reference: 'OWASP A01:2021, CWE-352'
  },
  {
    id: 'T-004',
    name: 'Broken Authentication',
    category: 'Authentication & Authorization',
    risk: 'Critical',
    description: 'Weak authentication mechanisms allowing unauthorized access',
    remediation: 'MFA, secure session management, account lockout, strong password hashing',
    detection: 'Failed login monitoring, session anomaly detection',
    reference: 'OWASP A07:2021, CWE-287'
  },
  {
    id: 'T-005',
    name: 'Sensitive Data Exposure',
    category: 'Data Protection',
    risk: 'High',
    description: 'Sensitive data transmitted or stored without proper protection',
    remediation: 'Encrypt at rest (AES-256), TLS 1.3 in transit, key management, data classification',
    detection: 'DLP tools, network traffic analysis, encryption audits',
    reference: 'OWASP A02:2021, CWE-311'
  },
  {
    id: 'T-006',
    name: 'XML External Entities (XXE)',
    category: 'Application Security',
    risk: 'Medium',
    description: 'XML parsers process external entity references in XML documents',
    remediation: 'Disable XML external entity processing, use less complex data formats',
    detection: 'XML parsing logs, SAST tools',
    reference: 'OWASP A04:2021, CWE-611'
  },
  {
    id: 'T-007',
    name: 'Broken Access Control',
    category: 'Access Control',
    risk: 'Critical',
    description: 'Users can act outside intended permissions',
    remediation: 'Implement RBAC/ABAC, deny by default, validate permissions server-side',
    detection: 'Access logs analysis, privilege escalation monitoring',
    reference: 'OWASP A01:2021, CWE-285'
  },
  {
    id: 'T-008',
    name: 'Security Misconfiguration',
    category: 'Configuration Management',
    risk: 'High',
    description: 'Insecure default configurations, incomplete setups, or verbose error messages',
    remediation: 'Hardening guides, automated configuration scanning, disable unnecessary features',
    detection: 'Configuration management tools, vulnerability scanners',
    reference: 'OWASP A05:2021, CWE-16'
  },
  {
    id: 'T-009',
    name: 'Insecure Deserialization',
    category: 'Application Security',
    risk: 'High',
    description: 'Untrusted data used to inflate objects leading to RCE',
    remediation: 'Avoid deserialization of untrusted data, implement integrity checks',
    detection: 'Application monitoring, deserialization event logging',
    reference: 'OWASP A08:2021, CWE-502'
  },
  {
    id: 'T-010',
    name: 'Using Components with Known Vulnerabilities',
    category: 'Infrastructure Security',
    risk: 'High',
    description: 'Outdated libraries and frameworks with known security flaws',
    remediation: 'Dependency scanning, patch management, SCA tools, version control',
    detection: 'SCA tools, CVE monitoring, dependency-check',
    reference: 'OWASP A06:2021, CWE-1035'
  },
  {
    id: 'T-011',
    name: 'Insufficient Logging & Monitoring',
    category: 'Logging & Monitoring',
    risk: 'Medium',
    description: 'Lack of proper logging preventing incident detection',
    remediation: 'Centralized logging, SIEM, log retention policies, alerting',
    detection: 'Log coverage assessment, incident response drills',
    reference: 'OWASP A09:2021, CWE-778'
  },
  {
    id: 'T-012',
    name: 'Unencrypted Data in Transit',
    category: 'Encryption',
    risk: 'High',
    description: 'Sensitive data transmitted over network without encryption',
    remediation: 'Enforce TLS 1.3, HTTPS only, certificate management, HSTS',
    detection: 'Network traffic analysis, SSL/TLS scanning',
    reference: 'CWE-319'
  },
  {
    id: 'T-013',
    name: 'Weak Password Policy',
    category: 'Authentication & Authorization',
    risk: 'Medium',
    description: 'Insufficient password complexity requirements',
    remediation: 'Enforce strong passwords, password expiration, breached password detection',
    detection: 'Password policy audits, credential stuffing monitoring',
    reference: 'CWE-521'
  },
  {
    id: 'T-014',
    name: 'Missing Network Segmentation',
    category: 'Network Security',
    risk: 'High',
    description: 'Flat network architecture allowing lateral movement',
    remediation: 'Implement VLANs, micro-segmentation, zero trust architecture',
    detection: 'Network topology analysis, traffic flow monitoring',
    reference: 'CWE-923'
  },
  {
    id: 'T-015',
    name: 'Exposed Management Interfaces',
    category: 'Network Security',
    risk: 'Critical',
    description: 'Admin panels, APIs, or management consoles accessible from internet',
    remediation: 'Restrict to internal networks, VPN access, IP whitelisting, MFA',
    detection: 'Port scanning, exposure monitoring, attack surface management',
    reference: 'CWE-425'
  },
  {
    id: 'T-016',
    name: 'Lack of Rate Limiting',
    category: 'API Security',
    risk: 'Medium',
    description: 'No throttling on API endpoints enabling abuse',
    remediation: 'Implement rate limiting, API gateway, throttling policies',
    detection: 'API traffic monitoring, abuse pattern detection',
    reference: 'CWE-770'
  },
  {
    id: 'T-017',
    name: 'Insecure API Endpoints',
    category: 'API Security',
    risk: 'High',
    description: 'APIs lacking proper authentication or exposing sensitive data',
    remediation: 'OAuth 2.0, API keys, input validation, API gateway',
    detection: 'API security testing, traffic analysis',
    reference: 'OWASP API Security Top 10'
  },
  {
    id: 'T-018',
    name: 'Missing Input Validation',
    category: 'Application Security',
    risk: 'High',
    description: 'Application accepts malformed or malicious input',
    remediation: 'Server-side validation, whitelisting, data type enforcement',
    detection: 'WAF, input fuzzing, DAST tools',
    reference: 'CWE-20'
  },
  {
    id: 'T-019',
    name: 'Hardcoded Credentials',
    category: 'Authentication & Authorization',
    risk: 'Critical',
    description: 'Passwords or API keys embedded in source code',
    remediation: 'Use secret management systems, environment variables, credential rotation',
    detection: 'SAST tools, secret scanning, code review',
    reference: 'CWE-798'
  },
  {
    id: 'T-020',
    name: 'Unpatched Systems',
    category: 'Infrastructure Security',
    risk: 'High',
    description: 'Operating systems and software not updated with security patches',
    remediation: 'Automated patch management, vulnerability scanning, patch testing',
    detection: 'Vulnerability scanners, patch compliance monitoring',
    reference: 'CWE-1104'
  },
  {
    id: 'T-021',
    name: 'Insecure Direct Object References (IDOR)',
    category: 'Access Control',
    risk: 'High',
    description: 'Direct access to objects via user-supplied input without authorization',
    remediation: 'Implement access control checks, use indirect references, validate ownership',
    detection: 'Authorization testing, access log analysis',
    reference: 'OWASP A01:2021, CWE-639'
  },
  {
    id: 'T-022',
    name: 'Server-Side Request Forgery (SSRF)',
    category: 'Application Security',
    risk: 'High',
    description: 'Application fetches remote resources based on user input',
    remediation: 'Validate and sanitize URLs, whitelist allowed domains, network segmentation',
    detection: 'Outbound traffic monitoring, request pattern analysis',
    reference: 'OWASP A10:2021, CWE-918'
  },
  {
    id: 'T-023',
    name: 'Clickjacking',
    category: 'Application Security',
    risk: 'Medium',
    description: 'Malicious site tricks users into clicking hidden elements',
    remediation: 'X-Frame-Options header, Content-Security-Policy frame-ancestors',
    detection: 'Header analysis, UI security testing',
    reference: 'CWE-1021'
  },
  {
    id: 'T-024',
    name: 'Open Redirects',
    category: 'Application Security',
    risk: 'Medium',
    description: 'Application redirects to untrusted URLs based on user input',
    remediation: 'Validate redirect URLs, use whitelist, avoid user-controlled redirects',
    detection: 'URL parameter analysis, redirect testing',
    reference: 'CWE-601'
  },
  {
    id: 'T-025',
    name: 'Missing Security Headers',
    category: 'Configuration Management',
    risk: 'Medium',
    description: 'Lack of HTTP security headers (CSP, HSTS, X-Content-Type-Options)',
    remediation: 'Implement all OWASP recommended security headers',
    detection: 'Header scanning tools, security baseline checks',
    reference: 'OWASP Secure Headers Project'
  },
  {
    id: 'T-026',
    name: 'Insecure File Upload',
    category: 'Application Security',
    risk: 'High',
    description: 'Unrestricted file upload allowing malicious file execution',
    remediation: 'File type validation, size limits, antivirus scanning, store outside webroot',
    detection: 'Upload monitoring, malware scanning',
    reference: 'CWE-434'
  },
  {
    id: 'T-027',
    name: 'Directory Traversal',
    category: 'Application Security',
    risk: 'High',
    description: 'Access to files outside intended directory',
    remediation: 'Input validation, path canonicalization, chroot jails',
    detection: 'File access monitoring, WAF',
    reference: 'CWE-22'
  },
  {
    id: 'T-028',
    name: 'Remote Code Execution (RCE)',
    category: 'Application Security',
    risk: 'Critical',
    description: 'Attacker executes arbitrary code on server',
    remediation: 'Input validation, sandboxing, least privilege, disable dangerous functions',
    detection: 'Process monitoring, anomaly detection, EDR',
    reference: 'CWE-94'
  },
  {
    id: 'T-029',
    name: 'Command Injection',
    category: 'Application Security',
    risk: 'Critical',
    description: 'Execution of arbitrary commands via vulnerable application',
    remediation: 'Avoid system calls, input validation, use APIs instead of shell commands',
    detection: 'Command execution monitoring, EDR',
    reference: 'CWE-78'
  },
  {
    id: 'T-030',
    name: 'Business Logic Vulnerabilities',
    category: 'Application Security',
    risk: 'High',
    description: 'Flaws in application logic allowing unauthorized operations',
    remediation: 'Thorough business logic testing, abuse case analysis, transaction validation',
    detection: 'Business transaction monitoring, fraud detection',
    reference: 'CWE-840'
  },
  {
    id: 'T-031',
    name: 'Session Fixation',
    category: 'Authentication & Authorization',
    risk: 'High',
    description: 'Attacker sets victim session ID to known value',
    remediation: 'Regenerate session IDs after login, secure session management',
    detection: 'Session tracking, authentication flow monitoring',
    reference: 'CWE-384'
  },
  {
    id: 'T-032',
    name: 'Privilege Escalation',
    category: 'Access Control',
    risk: 'Critical',
    description: 'User gains higher privileges than intended',
    remediation: 'Enforce principle of least privilege, validate permissions at each level',
    detection: 'Privilege monitoring, access anomaly detection',
    reference: 'CWE-269'
  },
  {
    id: 'T-033',
    name: 'Denial of Service (DoS)',
    category: 'Infrastructure Security',
    risk: 'High',
    description: 'Service made unavailable through resource exhaustion',
    remediation: 'Rate limiting, WAF, DDoS protection, capacity planning, auto-scaling',
    detection: 'Traffic monitoring, resource usage alerts',
    reference: 'CWE-400'
  },
  {
    id: 'T-034',
    name: 'Man-in-the-Middle (MitM)',
    category: 'Network Security',
    risk: 'Critical',
    description: 'Interception of communication between two parties',
    remediation: 'TLS/SSL, certificate pinning, HSTS, secure DNS',
    detection: 'Certificate monitoring, traffic analysis, IDS',
    reference: 'CWE-300'
  },
  {
    id: 'T-035',
    name: 'DNS Spoofing/Poisoning',
    category: 'Network Security',
    risk: 'High',
    description: 'Corrupt DNS data redirects traffic to malicious servers',
    remediation: 'DNSSEC, DNS filtering, secure DNS resolvers',
    detection: 'DNS query monitoring, anomaly detection',
    reference: 'CWE-350'
  },
  {
    id: 'T-036',
    name: 'Cloud Misconfiguration',
    category: 'Cloud Security',
    risk: 'Critical',
    description: 'Insecure cloud resource configurations (S3 buckets, IAM)',
    remediation: 'Cloud security posture management, least privilege IAM, encryption',
    detection: 'CSPM tools, cloud configuration audits',
    reference: 'OWASP Cloud Top 10'
  },
  {
    id: 'T-037',
    name: 'Container Escape',
    category: 'Container Security',
    risk: 'Critical',
    description: 'Breaking out of container isolation to access host',
    remediation: 'Secure container runtime, kernel hardening, rootless containers',
    detection: 'Container runtime monitoring, syscall monitoring',
    reference: 'CWE-653'
  },
  {
    id: 'T-038',
    name: 'Insecure Kubernetes Configuration',
    category: 'Container Security',
    risk: 'High',
    description: 'Misconfigured K8s cluster allowing unauthorized access',
    remediation: 'RBAC, network policies, pod security standards, admission controllers',
    detection: 'Kubernetes security scanners, audit logs',
    reference: 'CIS Kubernetes Benchmark'
  },
  {
    id: 'T-039',
    name: 'Supply Chain Attack',
    category: 'Infrastructure Security',
    risk: 'Critical',
    description: 'Compromise through third-party dependencies or vendors',
    remediation: 'Vendor risk assessment, SCA, SBOM, code signing, build pipeline security',
    detection: 'Supply chain monitoring, integrity verification',
    reference: 'NIST SSDF'
  },
  {
    id: 'T-040',
    name: 'Cryptographic Failures',
    category: 'Encryption',
    risk: 'High',
    description: 'Weak or broken cryptographic implementations',
    remediation: 'Use modern algorithms, proper key management, avoid deprecated protocols',
    detection: 'Cryptographic audits, SSL/TLS scanning',
    reference: 'OWASP A02:2021, CWE-327'
  }
];

app.get('/', (req, res) => {
  res.json({ 
    status: 'Server is running', 
    timestamp: new Date().toISOString(),
    threatScope: {
      total: THREAT_SCOPE.length,
      categories: [...new Set(THREAT_SCOPE.map(t => t.category))].length,
      critical: THREAT_SCOPE.filter(t => t.risk === 'Critical').length,
      high: THREAT_SCOPE.filter(t => t.risk === 'High').length,
      medium: THREAT_SCOPE.filter(t => t.risk === 'Medium').length,
      low: THREAT_SCOPE.filter(t => t.risk === 'Low').length
    }
  });
});

const getMethodologyPrompt = (methodology) => {
  const prompts = {
    'STRIDE': `Apply the STRIDE framework throughout the analysis.`,
    'PASTA': `Use the PASTA methodology.`,
    'VAST': `Apply VAST methodology.`,
    'OCTAVE': `Use OCTAVE framework.`,
    'MITRE_ATT&CK': `Apply MITRE ATT&CK framework.`,
    'DREAD': `Use DREAD scoring methodology.`,
    'CVSS': `Apply CVSS v3.1.`,
    'OWASP': `Apply OWASP Top 10.`,
    'NIST_RMF': `Use NIST RMF.`,
    'COMBINED': `Combined STRIDE + MITRE ATT&CK.`
  };
  
  return prompts[methodology] || prompts['STRIDE'];
};

app.post('/api/analyze', async (req, res) => {
  try {
    console.log('Received analysis request');
    
    const { apiKey, imageBase64, mediaType, methodology = 'STRIDE' } = req.body;
    
    if (!apiKey || !imageBase64 || !mediaType) {
      return res.status(400).json({ 
        error: 'Missing required fields'
      });
    }
    
    console.log(`Using ${methodology} with ${THREAT_SCOPE.length} predefined threats`);
    const anthropic = new Anthropic({ apiKey });
    const isPDF = mediaType === 'application/pdf';
    
    const methodologyPrompt = getMethodologyPrompt(methodology);
    
    // Create complete threat list
    const threatList = THREAT_SCOPE.map(t => 
      `${t.id}: ${t.name} (${t.category}) - Risk: ${t.risk}
   Description: ${t.description}
   Remediation: ${t.remediation}`
    ).join('\n\n');
    
    const message = await anthropic.messages.create({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 4096,
      messages: [
        {
          role: 'user',
          content: [
            {
              type: isPDF ? 'document' : 'image',
              source: { 
                type: 'base64', 
                media_type: mediaType, 
                data: imageBase64 
              }
            },
            { 
              type: 'text', 
              text: `You are an expert cybersecurity architect. Analyze this architecture diagram using ${methodology} methodology.

CRITICAL SCOPE LIMITATION: You MUST ONLY identify threats from this predefined list. DO NOT create threats outside this scope:

${threatList}

Format your response EXACTLY as follows:

# 1. ARCHITECTURE OVERVIEW

Provide overview including architecture pattern, data flows, trust boundaries, network topology.

# 2. IDENTIFIED COMPONENTS

- **[Component Name]**
  Type: [Type]
  Exposure: [External/Internal/Isolated]
  Description: [Description]

# 3. THREAT ANALYSIS (${methodology} Framework)

ONLY use threat IDs from the predefined list above. Identify which threats are ACTUALLY PRESENT in this specific architecture:

- **Threat ID: [Use exact ID from list, e.g. T-001]**
  Threat Name: [Exact name from list]
  Attack Vector: [How this threat manifests in THIS architecture]
  Impact: [CIA impact]
  Likelihood: [High/Medium/Low]
  Risk Score: [Use risk from predefined list]

# 4. IDENTIFIED VULNERABILITIES & MISCONFIGURATIONS

List specific vulnerabilities related to threats identified above.

# 5. MITIGATIONS & RECOMMENDATIONS

Use remediation strategies from the predefined threat list.

**Quick Wins (Immediate Actions):**
- [Specific mitigation from predefined list]

**Short-term Improvements (1-3 months):**
- [Specific improvement from predefined list]

**Long-term Strategic Changes:**
- [Strategic change]

# 6. COMPLIANCE CONSIDERATIONS

Relevant frameworks and compliance gaps.

${methodologyPrompt}

IMPORTANT: Only identify threats that ACTUALLY exist in this architecture. Use ONLY the threat IDs T-001 through T-040 from the predefined list.`
            }
          ]
        }
      ]
    });
    
    console.log('Analysis complete');
    res.json({ 
      content: message.content,
      scopedThreats: THREAT_SCOPE.length
    });
    
  } catch (error) {
    console.error('Error:', error.message);
    res.status(500).json({ 
      error: error.message
    });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Loaded ${THREAT_SCOPE.length} threats from scope`);
  console.log(`Categories: ${[...new Set(THREAT_SCOPE.map(t => t.category))].join(', ')}`);
});