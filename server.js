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
		const message = await anthropic.messages.create({
			model: 'claude-sonnet-4-20250514',
			max_tokens: 4096,
			messages: [
				{
					role: 'user',
					content: [
						{
							type: 'image',
							source: { type: 'base64', media_type: mediaType, data: imageBase64 }
						},
						{ type: 'text', text: `You are an expert cybersecurity architect and threat modeling specialist...` }
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