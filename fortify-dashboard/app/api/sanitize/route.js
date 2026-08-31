import { NextResponse } from 'next/server';
import { sanitizeObject } from '../../../../src/index';

export async function POST(request) {
  try {
    const { data } = await request.json();
    const { sanitized, strippedKeys, wasForbidden } = sanitizeObject(data || {});

    return NextResponse.json({
      original: data,
      sanitized,
      strippedKeys,
      wasForbidden
    });
  } catch (error) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}
