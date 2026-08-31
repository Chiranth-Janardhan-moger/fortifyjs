import { NextResponse } from 'next/server';
import { DetectionEngine } from '../../../../src/index';

const engine = new DetectionEngine();

export async function POST(request) {
  try {
    const body = await request.json();
    const payload = body.payload ?? '';
    
    const startTime = process.hrtime.bigint();
    const result = engine.detect(payload, { source: body.source });
    const endTime = process.hrtime.bigint();
    const latencyMs = Number(endTime - startTime) / 1e6;

    return NextResponse.json({
      payload,
      label: result.label,
      confidence: result.confidence,
      safe: result.label === 'benign' || result.confidence < 0.5,
      fastPath: result.fastPath || false,
      latencyMs: Number(latencyMs.toFixed(4)),
      scores: result.scores || {},
      matches: (result.matches || []).map(m => ({
        id: m.id,
        label: m.label,
        confidence: m.confidence
      }))
    });
  } catch (error) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}
