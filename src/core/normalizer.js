'use strict';

const SQL_IDENTIFIER = '(?:`[^`]+`|"[^"]+"|\\[[^\\]]+\\]|[A-Za-z_][\\w$]*)';
const SQL_WORD_BOOLEAN_OPERATOR = '(?:OR|AND|XOR)';
const SQL_SYMBOL_BOOLEAN_OPERATOR = '(?:\\|\\||&&)';
const SQL_BOOLEAN_OPERATOR = `(?:(?:\\b${SQL_WORD_BOOLEAN_OPERATOR}\\b)|${SQL_SYMBOL_BOOLEAN_OPERATOR})`;
const SQL_COMPARISON_OPERATOR = '(?:=|LIKE|!=|<>|<=|>=|<|>)';
const SQL_FUNCTION_CALL = `${SQL_IDENTIFIER}\\s*\\((?:[^()]|\\([^()]{0,120}\\)){0,240}\\)`;
const SQL_CONSTANT_VALUE = `(?:${SQL_FUNCTION_CALL}|\\d+(?:\\.\\d+)?|N?[\'"][^\'"]{0,80}[\'"]?|NULL)`;
const SQL_VALUE = `(?:${SQL_FUNCTION_CALL}|\\d+(?:\\.\\d+)?|N?[\'"][^\'"]{0,80}[\'"]?|[A-Za-z_][\\w.]*|NULL)`;
const SQL_CONSTANT_COMPARISON_EXPRESSION = `${SQL_CONSTANT_VALUE}\\s*${SQL_COMPARISON_OPERATOR}\\s*${SQL_CONSTANT_VALUE}`;
const SQL_COMPARISON_EXPRESSION = `${SQL_VALUE}\\s*${SQL_COMPARISON_OPERATOR}\\s*${SQL_VALUE}`;
const SQL_BETWEEN_EXPRESSION = `${SQL_VALUE}\\s+BETWEEN\\s+${SQL_VALUE}\\s+AND\\s+${SQL_VALUE}`;
const SQL_IS_EXPRESSION = `${SQL_VALUE}\\s+IS\\s+(?:NOT\\s+)?NULL`;
const SQL_EXISTS_EXPRESSION = `EXISTS\\s*\\(\\s*SELECT\\b`;
const SQL_BOOLEAN_LITERAL_EXPRESSION = '(?:TRUE|FALSE|UNKNOWN|NULL)';
const SQL_BOOLEAN_EXPRESSION = `(?:${SQL_COMPARISON_EXPRESSION}|${SQL_BETWEEN_EXPRESSION}|${SQL_IS_EXPRESSION}|${SQL_EXISTS_EXPRESSION}|${SQL_BOOLEAN_LITERAL_EXPRESSION})`;
const SQL_CONSTANT_BOOLEAN_EXPRESSION = `(?:${SQL_CONSTANT_COMPARISON_EXPRESSION}|${SQL_BETWEEN_EXPRESSION}|${SQL_IS_EXPRESSION}|${SQL_EXISTS_EXPRESSION}|${SQL_BOOLEAN_LITERAL_EXPRESSION})`;
const SQL_STACKED_STATEMENT_KEYWORD = '(?:SELECT|WITH|UNION|DROP|INSERT|UPDATE|DELETE|ALTER|CREATE|EXEC|EXECUTE|CALL|MERGE|TRUNCATE)';
const SQL_METADATA_OBJECT = '(?:information_schema(?:\\.[A-Za-z_][\\w$]*)?|sysobjects|sys\\.(?:tables|columns|objects|databases|schemas|indexes|all_columns)|sqlite_master|sqlite_schema|pg_catalog(?:\\.[A-Za-z_][\\w$]*)?|pg_(?:class|tables|namespace|attribute|database|user)|mysql\\.(?:innodb_table_stats|innodb_index_stats|user|db|tables_priv|columns_priv|proc|tables)|(?:all|user|dba)_(?:tables|tab_columns|objects|users|catalog|constraints|cons_columns|views))';
const SQL_METADATA_QUERY_CONTEXT = '(?:SELECT|FROM|JOIN|WHERE|COUNT\\s*\\(|EXISTS\\s*\\(|SHOW\\s+(?:FULL\\s+)?(?:TABLES|COLUMNS)|DESCRIBE|DESC)';
const HTTP_METHODS = ['all', 'get', 'post', 'put', 'patch', 'delete', 'head', 'options'];
const DEFAULT_REDACT_KEYS = ['password', 'passwd', 'pwd', 'token', 'secret', 'authorization', 'cookie', 'api_key', 'apikey'];
const NAMED_ENTITIES = {
  lt: '<',
  gt: '>',
  quot: '"',
  apos: "'",
  amp: '&',
  colon: ':',
  sol: '/',
  equals: '=',
  lpar: '(',
  rpar: ')',
  tab: '\t',
  newline: '\n',
  grave: '`'
};
const NAMED_ENTITY_PATTERN = new RegExp(`&(${Object.keys(NAMED_ENTITIES).sort((a, b) => b.length - a.length).join('|')});?`, 'gi');
const sqlWord = (word) => word.split('').join('[\\s\\u00a0]*');
class Normalizer {
  static decodeDeeply(payload, maxPayloadLength = 50000, maxDecodeIterations = 8) {
    return Normalizer.normalizePayload(payload, { sqlCommentMode: 'space' });
  }

  static normalizePayload(payload, { sqlCommentMode = 'space', maxPayloadLength = 50000, maxDecodeIterations = 8 } = {}) {
    if (Buffer.isBuffer(payload)) payload = payload.toString('utf8');
    if (typeof payload !== 'string') return '';
    if (payload.length > maxPayloadLength) {
      const headLength = Math.ceil(maxPayloadLength / 2);
      const tailLength = Math.floor(maxPayloadLength / 2);
      payload = `${payload.slice(0, headLength)}\nfortifyjs_TRUNCATED\n${tailLength > 0 ? payload.slice(-tailLength) : ''}`;
    }
    const decodeEntity = (match, hex, dec) => {
      const code = parseInt(hex || dec, hex ? 16 : 10);
      return Number.isFinite(code) && code <= 0x10ffff ? String.fromCodePoint(code) : match;
    };
    const decodeCodePoint = (match, hex) => {
      const code = parseInt(hex, 16);
      return Number.isFinite(code) && code <= 0x10ffff ? String.fromCodePoint(code) : match;
    };

    const normalize = (value) => {
      let normalized = value
        .replace(/%u([0-9a-fA-F]{4})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
        .replace(/\\u\{([0-9a-fA-F]{1,6})\}/g, decodeCodePoint)
        .replace(/\\u([0-9a-fA-F]{4})/g, decodeCodePoint)
        .replace(/\\x([0-9a-fA-F]{2})/g, decodeCodePoint)
        .replace(/&#x([0-9a-fA-F]+);?|&#(\d+);?/g, decodeEntity)
        .replace(NAMED_ENTITY_PATTERN, (match, name) => NAMED_ENTITIES[name.toLowerCase()] ?? match)
        .replace(/[\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]/g, ' ')
        .replace(/[\u200b-\u200d\ufeff]/g, '')
        .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
      try {
        normalized = normalized.normalize('NFKC');
      } catch (e) {}
      return normalized;
    };
    const decodePrintableBase64 = (candidate) => {
      try {
        const b64Decoded = Buffer.from(candidate, 'base64').toString('utf8');
        const nonPrintableCount = b64Decoded.replace(/[\t\r\n\x20-\x7E]/g, '').length;
        const isMostlyPrintable = b64Decoded.length > 0 && nonPrintableCount / b64Decoded.length < 0.1;
        return isMostlyPrintable && b64Decoded !== candidate ? b64Decoded : null;
      } catch (e) {
        return null;
      }
    };

    // Iterate decoding to catch multi-layer encoding
    let decoded = normalize(payload);
    let previous = "";
    let iterations = 0;
    while (decoded !== previous && iterations < maxDecodeIterations) {
      previous = decoded;
      try { 
        decoded = normalize(decodeURIComponent(decoded)); 
      } catch (e) { 
        decoded = normalize(decoded.replace(/%([0-9a-fA-F]{2})/g, (match, hex) => {
          try {
            return decodeURIComponent(match);
          } catch {
            return String.fromCharCode(parseInt(hex, 16));
          }
        }));
      }
      iterations++;
    }
    const base64Candidate = decoded;
    decoded = decoded.replace(/\bdata\s*:\s*([a-z0-9.+-]+\/[a-z0-9.+-]+)(?:;[a-z0-9=.+-]+)*;base64\s*,([A-Za-z0-9+/]+={0,2})/ig, (match, mimeType, data) => {
      if (!/^(?:text\/html|image\/svg\+xml|application\/xhtml\+xml)$/i.test(mimeType)) return match;
      const dataDecoded = decodePrintableBase64(data);
      const marker = /^image\/svg\+xml$/i.test(mimeType) ? '\nSVG_DATA_URI' : '';
      return dataDecoded ? `${match}${marker}\n${normalize(dataDecoded).replace(/\+/g, ' ')}` : match;
    });
    decoded = decoded.replace(/\+/g, ' ');
    if (/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(base64Candidate)) {
      const b64Decoded = decodePrintableBase64(base64Candidate);
      if (b64Decoded) decoded += `\n${normalize(b64Decoded).replace(/\+/g, ' ')}`;
    }
    if (sqlCommentMode === 'preserve') return decoded;
    // Preserve SQL block comments as separators so UNION/**/SELECT stays tokenized.
    // Detection also checks a removal variant to catch mid-keyword comment splits.
    decoded = decoded.replace(/\/\*!\d{0,6}\s*([\s\S]*?)\*\//g, (_, inner) => {
      const executableSql = inner.trim();
      if (sqlCommentMode === 'remove') return executableSql;
      return executableSql ? ` MYSQL_VERSIONED_COMMENT ${executableSql} ` : ' MYSQL_VERSIONED_COMMENT ';
    });
    decoded = decoded.replace(/\/\*[\s\S]*?\*\//g, sqlCommentMode === 'remove' ? '' : ' ');
    decoded = decoded.replace(/--[^\r\n]*(?=\r?\n|$)/g, ' ');
    decoded = decoded.replace(/#[^\r\n]*(?=\r?\n|$)/g, ' ');
    return decoded;
  }

  static payloadVariants(payload, options = {}) {
    const variants = [
      Normalizer.normalizePayload(payload, { sqlCommentMode: 'preserve' }),
      Normalizer.normalizePayload(payload, { sqlCommentMode: 'space' }),
      Normalizer.normalizePayload(payload, { sqlCommentMode: 'remove' })
    ];
    return [...new Set(variants.filter(Boolean))];
  }
}
module.exports = {
  Normalizer,
  SQL_IDENTIFIER,
  NAMED_ENTITIES,
  sqlWord
};
