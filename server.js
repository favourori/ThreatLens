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
const express = require('express');
const cors = require('cors');
const Anthropic = require('@anthropic-ai/sdk');

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// Health check endpoint
app.get('/', (req, res) => {
  res.json({ 
    status: 'Server is running', 
    timestamp: new Date().toISOString() 
  });
});

// Methodology-specific prompts
const getMethodologyPrompt = (methodology) => {
  const prompts = {
    'STRIDE': `Apply the STRIDE framework (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) throughout the analysis. Focus on identifying threats in each STRIDE category.`,
    
    'PASTA': `Use the PASTA (Process for Attack Simulation and Threat Analysis) methodology with these stages:
1. Define business objectives
2. Define technical scope
3. Application decomposition
4. Threat analysis
5. Vulnerability and weakness analysis
6. Attack modeling
7. Risk and impact analysis`,
    
    'VAST': `Apply VAST (Visual, Agile, and Simple Threat modeling) methodology:
- Create visual threat scenarios
- Focus on both application and operational threats
- Provide actionable, developer-friendly recommendations
- Consider both process flow and architectural risks`,
    
    'OCTAVE': `Use OCTAVE (Operationally Critical Threat, Asset, and Vulnerability Evaluation):
- Identify critical assets
- Profile threats to those assets
- Examine vulnerabilities and evaluate risks
- Develop protection strategy and mitigation plans`,
    
    'MITRE_ATT&CK': `Apply the MITRE ATT&CK framework:
- Map potential attack tactics and techniques
- Identify specific TTPs (Tactics, Techniques, and Procedures)
- Reference relevant ATT&CK technique IDs (e.g., T1078, T1190)
- Focus on realistic attack paths and adversary behaviors`,
    
    'DREAD': `Use DREAD scoring methodology:
- Damage: How bad would an attack be?
- Reproducibility: How easy is it to reproduce?
- Exploitability: How much work is needed to launch?
- Affected users: How many people will be impacted?
- Discoverability: How easy is it to discover?
Provide DREAD scores (1-10) for each threat.`,
    
    'CVSS': `Apply CVSS (Common Vulnerability Scoring System) v3.1:
- Provide Base Score metrics (Attack Vector, Attack Complexity, Privileges Required, User Interaction, Scope, CIA Impact)
- Calculate CVSS scores for identified vulnerabilities
- Include both Base Score and Environmental Score where applicable`,
    
    'OWASP': `Apply OWASP Top 10 and ASVS (Application Security Verification Standard):
- Map threats to OWASP Top 10 categories
- Apply ASVS verification levels
- Focus on web application security risks
- Include specific OWASP recommendations`,
    
    'NIST_RMF': `Use NIST Risk Management Framework (RMF):
- Categorize information system
- Select appropriate security controls
- Implement security controls
- Assess control effectiveness
- Authorize system operation
- Monitor security controls continuously`,
    
    'COMBINED': `Apply a combined approach using both STRIDE and MITRE ATT&CK:
- Use STRIDE categories for threat identification
- Map threats to MITRE ATT&CK tactics and techniques
- Provide ATT&CK technique IDs for each threat
- Create comprehensive coverage of both frameworks`
  };
  
  return prompts[methodology] || prompts['STRIDE'];
};

app.post('/api/analyze', async (req, res) => {
  try {
    console.log('Received analysis request');
    
    const { apiKey, imageBase64, mediaType, methodology = 'STRIDE' } = req.body;
    
    if (!apiKey || !imageBase64 || !mediaType) {
      return res.status(400).json({ 
        error: 'Missing required fields: apiKey, imageBase64, or mediaType' 
      });
    }
    
    console.log(`Using ${methodology} methodology`);
    const anthropic = new Anthropic({ apiKey });
    const isPDF = mediaType === 'application/pdf';
    
    const methodologyPrompt = getMethodologyPrompt(methodology);
    
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
              text: `You are an expert cybersecurity architect and threat modeling specialist. Analyze this architecture diagram in detail using the ${methodology} methodology.

CRITICAL: Format your response EXACTLY as shown below with clear sections and structured data:

# 1. ARCHITECTURE OVERVIEW

Provide a detailed overview of the architecture including:
- Overall architecture pattern
- Data flow description
- Trust boundaries and security zones
- Network topology

# 2. IDENTIFIED COMPONENTS

List each component in this format:
- **[Component Name]**
  Type: [Database/Web Server/API/Load Balancer/etc.]
  Exposure: [External/Internal/Isolated]
  Description: [Brief description of role and data handled]

# 3. THREAT ANALYSIS (${methodology} Framework)

For each threat, use this EXACT format:
- **Threat ID: T-001**
  Attack Vector: [Detailed description of how attack is executed]
  Impact: [What could be compromised - Confidentiality/Integrity/Availability]
  Likelihood: [High/Medium/Low]
  Risk Score: [Critical/High/Medium/Low]
  ${methodology === 'MITRE_ATT&CK' || methodology === 'COMBINED' ? 'MITRE ATT&CK Technique: [T1234 - Technique Name]' : ''}
  ${methodology === 'DREAD' ? 'DREAD Score: [D:X/R:X/E:X/A:X/D:X = Total]' : ''}

[Continue for all threats - identify at least 5-8 major threats]

# 4. IDENTIFIED VULNERABILITIES & MISCONFIGURATIONS

List each vulnerability:
- **[Vulnerability Name]**: [Detailed description of the security issue and potential impact]

# 5. MITIGATIONS & RECOMMENDATIONS

**Quick Wins (Immediate Actions):**
- [Specific actionable mitigation]: [Implementation details]

**Short-term Improvements (1-3 months):**
- [Specific improvement]: [Implementation details]

**Long-term Strategic Changes:**
- [Strategic change]: [Implementation details]

# 6. COMPLIANCE CONSIDERATIONS

- Relevant frameworks: [NIST, ISO 27001, SOC 2, etc.]
- Compliance gaps identified
- Recommended compliance actions

${methodologyPrompt}

Be specific, actionable, and thorough in your analysis.`
            }
          ]
        }
      ]
    });
    
    console.log('Analysis complete');
    res.json({ content: message.content });
    
  } catch (error) {
    console.error('Error during analysis:', error.message);
    res.status(500).json({ 
      error: error.message,
      details: error.error?.message || 'Unknown error'
    });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});