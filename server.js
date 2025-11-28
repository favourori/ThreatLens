// server.js
const express = require('express');
const cors = require('cors');
const Anthropic = require('@anthropic-ai/sdk');

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));

app.post('/api/analyze', async (req, res) => {
  try {
    const { apiKey, imageBase64, mediaType } = req.body;
    
    const anthropic = new Anthropic({ apiKey });
    
    // Check if it's a PDF
    const isPDF = mediaType === 'application/pdf';
    
    const message = await anthropic.messages.create({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 4096,
      messages: [
        {
          role: 'user',
          content: [
            {
              type: isPDF ? 'document' : 'image',  // 'document' for PDF, 'image' for images
              source: { 
                type: 'base64', 
                media_type: mediaType, 
                data: imageBase64 
              }
            },
            { 
              type: 'text', 
              text: `You are an expert cybersecurity architect and threat modeling specialist. Analyze this architecture diagram in detail.

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

# 3. THREAT ANALYSIS

For each threat, use this EXACT format:
- **Threat ID: T-001**
  Attack Vector: [Detailed description of how attack is executed]
  Impact: [What could be compromised - Confidentiality/Integrity/Availability]
  Likelihood: [High/Medium/Low]
  Risk Score: [Critical/High/Medium/Low]

- **Threat ID: T-002**
  Attack Vector: [Description]
  Impact: [Description]
  Likelihood: [High/Medium/Low]
  Risk Score: [Critical/High/Medium/Low]

[Continue for all threats - identify at least 5-8 major threats]

# 4. IDENTIFIED VULNERABILITIES & MISCONFIGURATIONS

List each vulnerability:
- **[Vulnerability Name]**: [Detailed description of the security issue and potential impact]
- **[Vulnerability Name]**: [Description]

# 5. MITIGATIONS & RECOMMENDATIONS

**Quick Wins (Immediate Actions):**
- [Specific actionable mitigation]: [Implementation details]
- [Specific actionable mitigation]: [Implementation details]

**Short-term Improvements (1-3 months):**
- [Specific improvement]: [Implementation details]
- [Specific improvement]: [Implementation details]

**Long-term Strategic Changes:**
- [Strategic change]: [Implementation details]
- [Strategic change]: [Implementation details]

# 6. COMPLIANCE CONSIDERATIONS

- Relevant frameworks: [NIST, ISO 27001, SOC 2, etc.]
- Compliance gaps identified
- Recommended compliance actions

Apply STRIDE framework (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) throughout the analysis. Be specific, actionable, and thorough.`
            }
          ]
        }
      ]
    });
    
    res.json({ content: message.content });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));