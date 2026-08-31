import { NextResponse } from 'next/server';
import {
  assertSafeCommand,
  assertSafePath,
  assertSafeUrl,
  assertSafeNoSql,
  assertSafeRedirect,
  assertSafeSqlQuery
} from '../../../../src/index';

export async function POST(request) {
  try {
    const { type, value } = await request.json();
    const startTime = process.hrtime.bigint();

    let safe = true;
    let error = null;
    let result = null;

    try {
      switch (type) {
        case 'command':
          result = assertSafeCommand(value);
          break;
        case 'path':
          result = assertSafePath(value, { rootDir: './uploads' });
          break;
        case 'url':
          result = assertSafeUrl(value, { allowPrivate: false });
          break;
        case 'nosql':
          result = assertSafeNoSql(typeof value === 'string' ? JSON.parse(value) : value);
          break;
        case 'redirect':
          result = assertSafeRedirect(value, { allowedHosts: ['myapp.com'] });
          break;
        case 'sql':
          result = assertSafeSqlQuery(value);
          break;
        default:
          safe = false;
          error = 'Unknown sink type';
      }
    } catch (err) {
      safe = false;
      error = err.message;
    }

    const endTime = process.hrtime.bigint();
    const latencyMs = Number(endTime - startTime) / 1e6;

    return NextResponse.json({
      type,
      value,
      safe,
      error,
      latencyMs: Number(latencyMs.toFixed(4))
    });
  } catch (error) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}
