import Anthropic from '@anthropic-ai/sdk';
import { v4 as uuidv4 } from 'uuid';

/**
 * Diagram Recognizer
 * Converts images of DFD/diagrams to structured JSON using Claude vision API
 */
class DiagramRecognizer {
  constructor() {
    this.client = new Anthropic();
  }

  /**
   * Extract base64 from image file or URL
   */
  async prepareImageData(imageInput) {
    let base64Data, mediaType;

    // If it's a file buffer
    if (Buffer.isBuffer(imageInput)) {
      base64Data = imageInput.toString('base64');
      mediaType = 'image/jpeg'; // default, can be enhanced
    }
    // If it's a base64 string
    else if (typeof imageInput === 'string' && imageInput.startsWith('data:')) {
      const match = imageInput.match(/data:([^;]+);base64,(.+)/);
      if (match) {
        mediaType = match[1];
        base64Data = match[2];
      } else {
        throw new Error('Invalid data URI format');
      }
    }
    // If it's already base64
    else if (typeof imageInput === 'string') {
      base64Data = imageInput;
      mediaType = 'image/jpeg';
    }
    // If it's a URL
    else if (typeof imageInput === 'string' && imageInput.startsWith('http')) {
      return { type: 'url', url: imageInput };
    } else {
      throw new Error('Invalid image input format');
    }

    return {
      type: 'base64',
      media_type: mediaType,
      data: base64Data
    };
  }

  /**
   * Analyze diagram image and extract DFD structure
   */
  async recognizeDiagram(imageInput, diagramType = 'dfd') {
    try {
      const imageData = await this.prepareImageData(imageInput);

      const prompt = `You are an expert at analyzing Data Flow Diagrams (DFD) and system architecture diagrams.

Analyze the provided diagram image and extract the following information:

1. **Entities/Elements**: Identify all elements (processes, data stores, actors, systems)
   - For each element, specify: id, name, type (process|datastore|actor|external_system), description

2. **Data Flows**: Identify all arrows/connections between elements
   - For each flow, specify: id, from (source element id), to (target element id), label/description

3. **Diagram Metadata**: 
   - Title of the diagram
   - Overall description
   - Any trust boundaries or security perimeters visible

Return a valid JSON object with this structure:
{
  "name": "diagram title",
  "description": "overall description",
  "type": "${diagramType}",
  "elements": [
    {
      "id": "unique_id",
      "name": "element name",
      "type": "process|datastore|actor|external_system",
      "description": "brief description"
    }
  ],
  "dataflows": [
    {
      "id": "unique_id",
      "from": "source_element_id",
      "to": "target_element_id",
      "label": "data flow description",
      "data": "type of data being transmitted"
    }
  ],
  "trustBoundaries": [
    {
      "id": "unique_id",
      "name": "boundary name",
      "elements": ["element_ids_inside"]
    }
  ]
}

Be thorough but conservative - only include elements and flows that are clearly visible in the diagram.
If confidence is low for any element, add a "confidence" field with the percentage (0-100).`;

      const imageContent = imageData.type === 'url'
        ? { type: 'image', source: { type: 'url', url: imageData.url } }
        : {
            type: 'image',
            source: {
              type: 'base64',
              media_type: imageData.media_type,
              data: imageData.data
            }
          };

      const response = await this.client.messages.create({
        model: 'claude-3-5-sonnet-20241022',
        max_tokens: 4096,
        messages: [
          {
            role: 'user',
            content: [
              imageContent,
              {
                type: 'text',
                text: prompt
              }
            ]
          }
        ]
      });

      // Extract JSON from response
      const responseText = response.content[0].type === 'text' ? response.content[0].text : '';
      const jsonMatch = responseText.match(/\{[\s\S]*\}/);

      if (!jsonMatch) {
        throw new Error('Could not extract JSON from Claude response');
      }

      const dfdData = JSON.parse(jsonMatch[0]);

      // Validate and ensure required fields
      return this.validateAndNormalizeDFD(dfdData);
    } catch (error) {
      throw new Error(`Diagram recognition failed: ${error.message}`);
    }
  }

  /**
   * Validate and normalize extracted DFD data
   */
  validateAndNormalizeDFD(dfdData) {
    // Ensure required fields
    const normalized = {
      name: dfdData.name || 'Imported Diagram',
      description: dfdData.description || '',
      type: dfdData.type || 'dfd',
      elements: [],
      dataflows: [],
      trustBoundaries: dfdData.trustBoundaries || []
    };

    // Process elements
    if (Array.isArray(dfdData.elements)) {
      normalized.elements = dfdData.elements.map(el => ({
        id: el.id || uuidv4(),
        name: el.name || 'Unnamed Element',
        type: this.normalizeElementType(el.type),
        description: el.description || '',
        confidence: el.confidence
      }));
    }

    // Process dataflows
    if (Array.isArray(dfdData.dataflows)) {
      normalized.dataflows = dfdData.dataflows.map(flow => ({
        id: flow.id || uuidv4(),
        from: flow.from,
        to: flow.to,
        label: flow.label || flow.data || 'Data',
        data: flow.data || 'Unknown Data Type',
        confidence: flow.confidence
      }));
    }

    return normalized;
  }

  /**
   * Normalize element types to standard DFD types
   */
  normalizeElementType(type) {
    const typeMap = {
      'process': 'process',
      'proc': 'process',
      'function': 'process',
      'datastore': 'datastore',
      'data store': 'datastore',
      'database': 'datastore',
      'db': 'datastore',
      'actor': 'actor',
      'user': 'actor',
      'person': 'actor',
      'external_system': 'external_system',
      'external system': 'external_system',
      'system': 'external_system',
      'service': 'external_system'
    };

    const normalized = typeMap[type?.toLowerCase()] || 'process';
    return normalized;
  }

  /**
   * Recognize multiple diagram types and merge if needed
   */
  async recognizeMultipleDiagrams(images, diagramType = 'dfd') {
    const results = [];

    for (const image of images) {
      try {
        const recognized = await this.recognizeDiagram(image, diagramType);
        results.push({
          success: true,
          data: recognized
        });
      } catch (error) {
        results.push({
          success: false,
          error: error.message
        });
      }
    }

    return results;
  }
}

export default new DiagramRecognizer();
