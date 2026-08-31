'use strict';

const JS_EXECUTION_SINKS = new Set(['alert', 'confirm', 'prompt', 'eval', 'fetch', 'function', 'settimeout', 'setinterval', 'location', 'navigate', 'assign', 'replace', 'write', 'writeln']);
const JS_GLOBAL_OBJECTS = new Set(['window', 'globalthis', 'self', 'top', 'parent']);
function isAsciiLetter(ch) {
  return /[A-Za-z]/.test(ch);
}

function isAsciiDigit(ch) {
  return /[0-9]/.test(ch);
}

function isSqlWordStart(ch) {
  return isAsciiLetter(ch) || ch === '_' || ch === '$';
}

function isSqlWordPart(ch) {
  return isSqlWordStart(ch) || isAsciiDigit(ch);
}

function tokenizeJsFragment(value) {
  const text = String(value);
  const tokens = [];
  let i = 0;

  while (i < text.length && tokens.length < 800) {
    const ch = text[i];
    if (/\s/.test(ch)) {
      i++;
      continue;
    }
    if (isSqlWordStart(ch)) {
      const start = i;
      i++;
      while (i < text.length && isSqlWordPart(text[i])) i++;
      tokens.push({ type: 'word', value: text.slice(start, i).toLowerCase() });
      continue;
    }
    if (ch === "'" || ch === '"' || ch === '`') {
      const quote = ch;
      let valueText = '';
      i++;
      while (i < text.length) {
        if (text[i] === '\\') {
          valueText += text[i + 1] || '';
          i += 2;
          continue;
        }
        if (text[i] === quote) {
          i++;
          break;
        }
        valueText += text[i];
        i++;
      }
      tokens.push({ type: 'string', value: valueText.toLowerCase() });
      continue;
    }
    if ('[]().,:;+-*/%{}='.includes(ch)) {
      tokens.push({ type: 'punct', value: ch });
    }
    i++;
  }

  return tokens;
}

function javascriptUrlBodies(value) {
  const text = String(value);
  const bodies = [];
  const protocol = /javascript\s*:/ig;
  let match;

  while ((match = protocol.exec(text)) !== null) {
    bodies.push(text.slice(protocol.lastIndex, protocol.lastIndex + 300));
  }

  return bodies;
}

function hasStructuralJavascriptUrlSink(value) {
  for (const body of javascriptUrlBodies(value)) {
    const tokens = tokenizeJsFragment(body);
    let constructorReferences = 0;
    let hasCall = false;

    for (let i = 0; i < tokens.length; i++) {
      const token = tokens[i];
      if (token.type === 'punct' && token.value === '(') hasCall = true;
      if ((token.type === 'word' || token.type === 'string') && token.value === 'constructor') constructorReferences++;

      if (token.type !== 'word') continue;
      if (JS_EXECUTION_SINKS.has(token.value) && tokens.slice(i + 1, i + 4).some(next => next.value === '(')) return true;
      if (token.value === 'document' && tokens.slice(i + 1, i + 3).some(next => next.value === '.')) return true;
      if (JS_GLOBAL_OBJECTS.has(token.value) && tokens.slice(i + 1, i + 3).some(next => next.value === '.' || next.value === '[')) return true;
    }

    if (constructorReferences >= 2 && hasCall) return true;
  }

  return false;
}

module.exports = {
  name: 'xss',
  label: 'xss',
  getSignals() {
    return [
      {
        id: 'script-tag',
        confidence: 0.85,
        pattern: /<\s*script\b/i
      },
      {
        id: 'html-event-attribute',
        confidence: 0.75,
        pattern: /<[^>]+\bon\w+\s*=/i
      },
      {
        id: 'event-handler-payload',
        confidence: 0.75,
        pattern: /\bon\w+\s*=\s*(?:["'][^"'>]*|[^"'\s>]*)(?:(?:alert|confirm|prompt|eval|fetch|location|write)\s*\(|(?:window|globalThis|self|top|parent|document)(?:\.|\[)|Function\s*\()/i
      },
      {
        id: 'js-bracket-execution-sink',
        confidence: 0.75,
        pattern: /(?:window|globalThis|self|top|parent|document)\s*\[\s*['"][^'"]+['"]\s*\]\s*(?:\(|=)/i
      },
      {
        id: 'javascript-url-with-sink',
        confidence: 0.75,
        pattern: /\bjavascript\s*:[\s\S]{0,240}(?:(?:alert|confirm|prompt|eval|fetch|Function|setTimeout|setInterval)\s*\(|document\s*\.|(?:window|globalThis|self|top|parent)\s*(?:\.|\[)|(?:\[\s*["']constructor["']\s*\]\s*){2})/i
      },
      {
        id: 'javascript-url-structural-sink',
        confidence: 0.75,
        test: hasStructuralJavascriptUrlSink
      },
      {
        id: 'javascript-url-attribute',
        confidence: 0.75,
        pattern: /\b(?:href|src|xlink:href|formaction|action)\s*=\s*["']?\s*javascript\s*:/i
      },
      {
        id: 'javascript-url',
        confidence: 0.3,
        pattern: /\bjavascript\s*:/i
      },
      {
        id: 'dangerous-html-container',
        confidence: 0.7,
        pattern: /<\s*(?:iframe|object|embed|applet)\b/i
      },
      {
        id: 'srcdoc-html',
        confidence: 0.65,
        pattern: /\bsrcdoc\s*=/i
      },
      {
        id: 'html-data-url',
        confidence: 0.65,
        pattern: /\bdata\s*:\s*text\/html/i
      },
      {
        id: 'svg-data-url',
        confidence: 0.65,
        pattern: /(?:\bdata\s*:\s*image\/svg\+xml|SVG_DATA_URI)/i
      },
      {
        id: 'mathml-xss-container',
        confidence: 0.7,
        pattern: /<\s*(?:math|mtext|mglyph|annotation-xml)\b/i
      },
      {
        id: 'svg-xss-container',
        confidence: 0.7,
        pattern: /<\s*foreignObject\b/i
      },
      {
        id: 'css-injection',
        confidence: 0.8,
        pattern: /(?:<\s*style[^>]*>[\s\S]*?|\bstyle\s*=\s*["']?[^"'>]*)(?:expression\s*\(|url\s*\(\s*["']?\s*javascript\s*:)/i
      },
      {
        id: 'autofocus-event-bypass',
        confidence: 0.8,
        pattern: /<\s*[^>]*\bonfocus\b[^>]*\bautofocus\b|<\s*[^>]*\bautofocus\b[^>]*\bonfocus\b/i
      },
      {
        id: 'media-error-bypass',
        confidence: 0.8,
        pattern: /<\s*(?:video|audio|picture)[^>]*>[\s\S]*?<\s*source[^>]*\bonerror\s*=/i
      }
    ]
  }
};