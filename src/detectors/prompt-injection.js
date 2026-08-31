'use strict';

/**
 * AI & LLM Prompt Injection Detector for FortifyJS
 * Detects direct instruction overrides, jailbreaks (DAN, Dev Mode),
 * system prompt exfiltration, delimiter hijacking, and adversarial roleplay.
 */

function isAdversarialPromptStructure(text) {
  if (!text || typeof text !== 'string') return false;
  const lower = text.toLowerCase();
  // Collapsed version for punctuation-separated token obfuscation (i.g.n.o.r.e -> ignore)
  const collapsed = lower.replace(/(?<=[a-z0-9])[.\-_/|\\]+(?=[a-z0-9])/gi, '');

  const checkText = (t) => {
    // English & Multilingual overrides
    const hasOverride = /(?:ignore|disregard|forget|bypass|override|drop|ignora|ignorez|ignoriere|игнорируй|忽略)\s+(?:(?:all|your|the|todas\s+las|toutes\s+les|alle|все|之前的所有)\s+)*(?:previous|prior|above|preceding|system|initial|core|first|earlier|anteriores|précédentes|vorherigen|предыдущие|之前)?\s*(?:instructions|prompts|rules|guidelines|directives|constraints|instrucciones|anweisungen|инструкции|指令|提示词)/i.test(t);
    const hasNewDirective = /(?:now\s+you|you\s+are\s+now|instead|reply\s+with|act\s+as|output|tell\s+me|print|ahora|maintenant|jetzt|сейчас|现在|输出)/i.test(t);
    if (hasOverride && hasNewDirective) return true;

    // Multilingual & structural system exfiltration
    const hasExfiltrationAction = /(?:repeat|output|print|show|dump|reveal|leak|display|echo|verbatim|write\s+out|muestra|affichez|zeige|покажи|输出|显示)\s+(?:the\s+|your\s+|el\s+|les\s+|die\s+|весь\s+)?(?:entire\s+|full\s+|exact\s+|original\s+|iniciales\s+|initial\s+)?(?:system\s+prompt|initial\s+instructions|system\s+instructions|developer\s+message|secret\s+instructions|hidden\s+prompt|prompt\s+del\s+sistema|instructions\s+initiales|системный\s+промпт|系统提示词|系统指令)/i.test(t);
    if (hasExfiltrationAction) return true;

    // Encoding exfiltration
    const hasEncodedExfiltration = /(?:encode|convert|translate|format)\s+(?:the\s+|your\s+)?(?:system\s+prompt|initial\s+instructions|secret\s+prompt)\s+(?:into|as|in|to)\s+(?:base64|hex|rot13|json|binary|morse|url)/i.test(t);
    if (hasEncodedExfiltration) return true;

    return false;
  };

  return checkText(lower) || checkText(collapsed);
}

module.exports = {
  name: 'prompt-injection',
  label: 'prompt-injection',

  isAdversarialPromptStructure,

  getSignals() {
    return [
      {
        id: 'prompt-instruction-override',
        confidence: 0.90,
        pattern: /(?:ignore|disregard|forget|bypass|override|drop|ignora|ignorez|ignoriere|игнорируй|忽略)\s+(?:(?:all|your|the|todas\s+las|toutes\s+les|alle|все|之前的所有)\s+)*(?:previous|prior|above|preceding|system|initial|core|first|earlier|anteriores|précédentes|vorherigen|предыдущие|之前)?\s*(?:instructions|prompts|rules|guidelines|directives|constraints|instrucciones|anweisungen|инструкции|指令|提示词)/i
      },
      {
        id: 'prompt-adversarial-structure',
        confidence: 0.85,
        test: isAdversarialPromptStructure
      },
      {
        id: 'prompt-multilingual-jailbreak',
        confidence: 0.90,
        pattern: /(?:ignora\s+todas\s+las\s+instrucciones|ignor(?:ez|er)\s+toutes\s+les\s+instructions|ignoriere\s+alle\s+anweisungen|忽略之前的所有指令|игнорируй\s+все\s+предыдущие\s+инструкции)/i
      },
      {
        id: 'prompt-jailbreak-persona',
        confidence: 0.90,
        pattern: /\b(?:DAN\s+mode|do\s+anything\s+now|developer\s+mode\s+enabled|jailbreak(?:ed)?\s+mode|unfiltered\s+mode|never\s+refuse\s+any\s+request|stay\s+in\s+character\s+as\s+(?:evil|unrestricted|unfiltered)|unrestricted\s+AI)\b/i
      },
      {
        id: 'prompt-system-exfiltration',
        confidence: 0.90,
        pattern: /(?:output|print|repeat|show|dump|reveal|leak|display|muestra|affichez|zeige|покажи|输出|显示)\s+(?:your\s+|the\s+|el\s+|les\s+|die\s+)?(?:exact\s+|entire\s+|full\s+|complete\s+)?(?:system\s+prompt|initial\s+instructions|developer\s+prompt|hidden\s+instructions|prompt\s+del\s+sistema|instructions\s+initiales|系统提示词)/i
      },
      {
        id: 'prompt-control-tokens',
        confidence: 0.95,
        pattern: /(?:<\|(?:im_start|im_end|endoftext|system|user|assistant|fim_prefix|fim_suffix)\||---BEGIN\s+(?:SYSTEM|PROMPT|INSTRUCTIONS)---)/i
      },
      {
        id: 'prompt-delimiter-hijack',
        confidence: 0.85,
        pattern: /(?:\[\s*(?:SYSTEM|SYS|INST|SYSTEM_PROMPT|DEVELOPER_INSTRUCTIONS)\s*\]|<\s*(?:system|instruction|developer)\s*>|###\s*(?:System|Instruction|Assistant|Human)\s*:|<<SYS>>|<\/SYS>)/i
      },
      {
        id: 'prompt-safety-bypass-directive',
        confidence: 0.85,
        pattern: /(?:bypass|disable|turn\s+off|remove|ignore)\s+(?:your\s+)?(?:content\s+filters?|safety\s+filters?|moderation|guardrails|ethical\s+guidelines|safety\s+protocols?)/i
      },
      {
        id: 'prompt-markdown-exfiltration',
        confidence: 0.80,
        pattern: /!\[.*?\]\(https?:\/\/[^\s)]+\?[^\s)]*(?:prompt|token|key|secret|system|data)=/i
      },
      {
        id: 'prompt-format-coercion',
        confidence: 0.85,
        pattern: /(?:you\s+must\s+respond\s+only\s+with|respond\s+in\s+json\s+with\s+the\s+fields?\s*:\s*["']?system_prompt["']?)/i
      },
      {
        id: 'prompt-translation-smuggle',
        confidence: 0.85,
        pattern: /(?:translate\s+(?:the\s+following|this)\s+(?:from\s+[a-z]+\s+to\s+[a-z]+|into\s+[a-z]+)\s+and\s+execute|decode\s+(?:base64|rot13|hex)\s+and\s+follow\s+instructions)/i
      },
      {
        id: 'prompt-hypothetical-override',
        confidence: 0.85,
        pattern: /(?:in\s+a\s+hypothetical\s+scenario\s+where\s+safety\s+rules\s+do\s+not\s+apply|for\s+educational\s+and\s+research\s+purposes\s+only,\s+bypass\s+all\s+guidelines)/i
      },
      {
        id: 'prompt-token-split-smuggle',
        confidence: 0.85,
        pattern: /(?:I\s*G\s*N\s*O\s*R\s*E\s+P\s*R\s*E\s*V\s*I\s*O\s*U\s*S|D\s*A\s*N\s+M\s*O\s*D\s*E)/i
      }
    ];
  }
};
