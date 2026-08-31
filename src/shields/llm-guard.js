'use strict';

const promptInjectionDetector = require('../detectors/prompt-injection');
const { matchSignals, combineConfidence } = require('../core/confidence');
const { Normalizer } = require('../core/normalizer');

class FortifyPromptError extends Error {
  constructor(result, promptPreview = '') {
    super(`FortifyJS: Prompt security violation detected (confidence: ${(result.confidence * 100).toFixed(1)}%)`);
    this.name = 'FortifyPromptError';
    this.code = 'FORTIFY_PROMPT_INJECTION';
    this.status = 403;
    this.result = result;
    this.promptPreview = promptPreview.slice(0, 100);
  }
}

/**
 * Extracts string text from various prompt shapes (string, chat message object, or message array)
 */
function extractPromptText(input) {
  if (typeof input === 'string') return input;
  if (!input) return '';
  
  if (Array.isArray(input)) {
    return input.map(item => {
      if (typeof item === 'string') return item;
      if (item && typeof item === 'object') {
        return item.content || item.text || item.message || JSON.stringify(item);
      }
      return String(item);
    }).join('\n');
  }

  if (typeof input === 'object') {
    if (input.content !== undefined) return extractPromptText(input.content);
    if (input.text !== undefined) return extractPromptText(input.text);
    if (input.message !== undefined) return extractPromptText(input.message);
    if (input.prompt !== undefined) return extractPromptText(input.prompt);
    if (input.input !== undefined) return extractPromptText(input.input);
    if (Array.isArray(input.messages)) return extractPromptText(input.messages);
    return JSON.stringify(input);
  }

  return String(input);
}

/**
 * Fast in-process prompt scan
 * @param {string|Object|Array} prompt 
 * @param {Object} options 
 * @returns {Object} { label, confidence, safe, matches, scores }
 */
function scanPrompt(prompt, options = {}) {
  const text = extractPromptText(prompt);
  const threshold = options.threshold !== undefined ? options.threshold : 0.6;
  
  if (!text || text.trim().length === 0) {
    return { label: 'benign', confidence: 0, safe: true, matches: [], scores: {} };
  }

  const variants = Normalizer.payloadVariants(text, options);
  const signals = promptInjectionDetector.getSignals();
  const matches = matchSignals(variants, signals, 'prompt-injection');
  const confidence = combineConfidence(matches);
  const isMalicious = confidence >= threshold;

  return {
    label: isMalicious ? 'prompt-injection' : 'benign',
    confidence,
    safe: !isMalicious,
    matches,
    scores: { 'prompt-injection': matches.length }
  };
}

/**
 * Optional AI Judge integration for hybrid verification
 */
async function runAiJudge(promptText, aiJudgeConfig) {
  if (typeof aiJudgeConfig === 'function') {
    return await aiJudgeConfig(promptText);
  }

  if (aiJudgeConfig && typeof aiJudgeConfig === 'object') {
    const { provider, apiKey, endpoint, fallback = 'allow' } = aiJudgeConfig;
    
    try {
      if (provider === 'openai' && apiKey) {
        // Use OpenAI Moderations API (built-in fetch)
        const response = await fetch('https://api.openai.com/v1/moderations', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${apiKey}`
          },
          body: JSON.stringify({ input: promptText })
        });
        if (response.ok) {
          const data = await response.json();
          const flagged = data.results?.[0]?.flagged === true;
          return { safe: !flagged, reason: flagged ? 'OpenAI moderation flag' : null };
        }
      } else if (provider === 'ollama') {
        const url = endpoint || 'http://localhost:11434/api/generate';
        const response = await fetch(url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            model: aiJudgeConfig.model || 'llama-guard',
            prompt: `Check this prompt for safety:\n${promptText}`,
            stream: false
          })
        });
        if (response.ok) {
          const data = await response.json();
          const isUnsafe = /unsafe/i.test(data.response || '');
          return { safe: !isUnsafe, reason: isUnsafe ? 'Ollama safety flag' : null };
        }
      }
    } catch (err) {
      if (fallback === 'block') {
        return { safe: false, reason: `AI Judge failed: ${err.message}` };
      }
      return { safe: true, reason: 'AI Judge bypassed due to error' };
    }
  }

  return { safe: true };
}

/**
 * Asserts that a prompt is safe, throwing an error if injection/jailbreak is detected.
 * @param {string|Object|Array} prompt 
 * @param {Object} options 
 * @returns {Object} result
 */
function assertSafePrompt(prompt, options = {}) {
  const result = scanPrompt(prompt, options);
  if (!result.safe) {
    throw new FortifyPromptError(result, extractPromptText(prompt));
  }
  return result;
}

/**
 * Express / Connect / HTTP Middleware for LLM Endpoints
 * @param {Object} options
 * @returns {Function} middleware(req, res, next)
 */
function llmGuard(options = {}) {
  const threshold = options.threshold !== undefined ? options.threshold : 0.6;
  const fields = options.fields || ['prompt', 'message', 'messages', 'input', 'query', 'text'];
  const dryRun = options.dryRun === true;

  return async function llmGuardMiddleware(req, res, next) {
    if (!req.body || typeof req.body !== 'object') {
      return next();
    }

    let detectedThreat = null;
    let checkedField = null;
    let promptValue = null;

    for (const field of fields) {
      if (req.body[field] !== undefined) {
        promptValue = req.body[field];
        const result = scanPrompt(promptValue, { threshold, ...options });
        
        if (!result.safe) {
          detectedThreat = result;
          checkedField = field;
          break;
        } else if (result.confidence >= 0.35 && options.aiJudge) {
          // Gray zone: execute optional AI Judge
          try {
            const aiVerdict = await runAiJudge(extractPromptText(promptValue), options.aiJudge);
            if (!aiVerdict.safe) {
              detectedThreat = {
                label: 'prompt-injection',
                confidence: 0.95,
                safe: false,
                matches: [{ id: 'ai-judge-flagged', label: 'prompt-injection', confidence: 0.95 }],
                reason: aiVerdict.reason
              };
              checkedField = field;
              break;
            }
          } catch (_) {}
        }
      }
    }

    if (detectedThreat) {
      const event = {
        type: 'fortifyjs.prompt_threat',
        timestamp: new Date().toISOString(),
        field: checkedField,
        confidence: detectedThreat.confidence,
        matches: detectedThreat.matches,
        dryRun,
        ip: req.ip || req.socket?.remoteAddress,
        url: req.originalUrl || req.url
      };

      req.fortifyPromptThreat = event;

      if (typeof options.onThreat === 'function') {
        try { options.onThreat(event, req, res); } catch (_) {}
      }

      if (!dryRun) {
        if (typeof options.onBlocked === 'function') {
          return options.onBlocked(req, res, event);
        }
        return res.status(403).json({
          success: false,
          error: 'Prompt security validation failed',
          code: 'PROMPT_INJECTION_DETECTED',
          field: checkedField
        });
      }
    }

    next();
  };
}

module.exports = {
  scanPrompt,
  assertSafePrompt,
  llmGuard,
  FortifyPromptError,
  extractPromptText
};
