import { NextResponse } from 'next/server';
import { scanPrompt } from '../../../../src/index';

export async function POST(request) {
  try {
    const body = await request.json();
    const prompt = body.prompt ?? '';
    
    const startTime = process.hrtime.bigint();
    const verdict = scanPrompt(prompt, { threshold: 0.6 });
    const endTime = process.hrtime.bigint();
    const latencyMs = Number(endTime - startTime) / 1e6;

    return NextResponse.json({
      prompt,
      safe: verdict.safe,
      label: verdict.label,
      confidence: verdict.confidence,
      latencyMs: Number(latencyMs.toFixed(4)),
      matches: verdict.matches || [],
      scores: verdict.scores || {}
    });
  } catch (error) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}
