import OpenAI from 'openai';

const client = new OpenAI({
  apiKey: process.env.PERPLEXITY_API_KEY,
  baseURL: 'https://api.perplexity.ai',
});

/**
 * extractDfdFromImage
 *
 * This helper sends a diagram image (PNG/JPEG) to Perplexity's vision model
 * and asks it to infer a DFD-like JSON structure compatible with our
 * dfdValidator + threatGenerator.
 */
export async function extractDfdFromImage(buffer, mimeType = 'image/png') {
  if (!process.env.PERPLEXITY_API_KEY) {
    throw new Error('PERPLEXITY_API_KEY is not set in the environment');
  }

  const base64 = buffer.toString('base64');

  const prompt = `You are a senior security architect.
You are given a picture of a system diagram (DFD or similar).

Your task is to EXTRACT a minimal but valid DFD JSON object compatible with this TypeScript-like structure:

interface DfdElement {
  id: string;
  name: string;
  type: 'actor' | 'process' | 'datastore' | 'external_entity';
  description?: string;
  trustLevel?: 'trusted' | 'partially-trusted' | 'untrusted';
}

interface DfdDataflow {
  id: string;
  name: string;
  from: string; // element id
  to: string;   // element id
  description?: string;
  protocol?: string;
  hasSensitiveData?: boolean;
  isEncrypted?: boolean;
  isCrossNetwork?: boolean;
}

interface DfdModel {
  id: string;
  name: string;
  description?: string;
  elements: DfdElement[];
  dataflows: DfdDataflow[];
  trustBoundaries?: { id: string; name: string; elements: string[] }[];
}

Return STRICTLY valid JSON for DfdModel, no markdown, no explanation.`;

  const response = await client.chat.completions.create({
    model: 'sonar-pro-vision',
    temperature: 0.2,
    messages: [
      {
        role: 'system',
        content: 'You extract structured DFD JSON from architecture and DFD diagram images for automated threat modeling.',
      },
      {
        role: 'user',
        content: [
          {
            type: 'text',
            text: prompt,
          },
          {
            type: 'image_url',
            image_url: {
              url: `data:${mimeType};base64,${base64}`,
            },
          },
        ],
      },
    ],
  });

  const raw = response.choices?.[0]?.message?.content || '';

  let text = typeof raw === 'string' ? raw : '';

  // Some models may wrap JSON in markdown fences; strip them defensively.
  text = text.trim();
  if (text.startsWith('```')) {
    text = text.replace(/^```[a-zA-Z]*\n?/, '').replace(/```$/, '').trim();
  }

  const dfd = JSON.parse(text);

  if (!dfd.elements || !dfd.dataflows) {
    throw new Error('Extracted DFD JSON is missing required fields');
  }

  return dfd;
}
