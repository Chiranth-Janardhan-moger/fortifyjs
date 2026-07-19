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
const SQL_CONSTANT_BETWEEN = `${SQL_CONSTANT_VALUE}\\s+BETWEEN\\s+${SQL_CONSTANT_VALUE}\\s+AND\\s+${SQL_CONSTANT_VALUE}`;
const SQL_IS_EXPRESSION = `${SQL_VALUE}\\s+IS\\s+(?:NOT\\s+)?NULL`;
const SQL_CONSTANT_IS = `${SQL_CONSTANT_VALUE}\\s+IS\\s+(?:NOT\\s+)?NULL`;
const SQL_EXISTS_EXPRESSION = `EXISTS\\s*\\(\\s*SELECT\\b`;
const SQL_BOOLEAN_LITERAL_EXPRESSION = '(?:TRUE|FALSE|UNKNOWN|NULL)';
const SQL_BOOLEAN_EXPRESSION = `(?:${SQL_COMPARISON_EXPRESSION}|${SQL_BETWEEN_EXPRESSION}|${SQL_IS_EXPRESSION}|${SQL_EXISTS_EXPRESSION}|${SQL_BOOLEAN_LITERAL_EXPRESSION})`;
const SQL_CONSTANT_BOOLEAN_EXPRESSION = `(?:${SQL_CONSTANT_COMPARISON_EXPRESSION}|${SQL_CONSTANT_BETWEEN}|${SQL_CONSTANT_IS}|${SQL_EXISTS_EXPRESSION}|${SQL_BOOLEAN_LITERAL_EXPRESSION})`;
const SQL_STACKED_STATEMENT_KEYWORD = '(?:SELECT|WITH|UNION|DROP|INSERT|UPDATE|DELETE|ALTER|CREATE|EXEC|EXECUTE|CALL|MERGE|TRUNCATE)';
const SQL_METADATA_OBJECT = '(?:information_schema(?:\\.[A-Za-z_][\\w$]*)?|sysobjects|sys\\.(?:tables|columns|objects|databases|schemas|indexes|all_columns)|sqlite_master|sqlite_schema|pg_catalog(?:\\.[A-Za-z_][\\w$]*)?|pg_(?:class|tables|namespace|attribute|database|user)|mysql\\.(?:innodb_table_stats|innodb_index_stats|user|db|tables_priv|columns_priv|proc|tables)|(?:all|user|dba)_(?:tables|tab_columns|objects|users|catalog|constraints|cons_columns|views))';
const SQL_METADATA_QUERY_CONTEXT = '(?:SELECT|FROM|JOIN|WHERE|COUNT\\s*\\(|EXISTS\\s*\\(|SHOW\\s+(?:FULL\\s+)?(?:TABLES|COLUMNS)|DESCRIBE|DESC)';
const sqlWord = (word) => word.split('').join('[\\s\\u00a0]*');
const unionSelectPattern = (wordBuilder = word => word) => `\\b${wordBuilder('UNION')}(?:\\s+(?:${wordBuilder('ALL')}|${wordBuilder('DISTINCT')})\\s+|\\s+|\\s*\\(\\s*)${wordBuilder('SELECT')}\\b`;
const unionValuesPattern = (wordBuilder = word => word) => `\\b${wordBuilder('UNION')}(?:\\s+(?:${wordBuilder('ALL')}|${wordBuilder('DISTINCT')})\\s+|\\s+|\\s*\\(\\s*)${wordBuilder('VALUES')}\\s*\\(`;
const SQL_BOOLEAN_WORDS = new Set(['OR', 'AND', 'XOR']);
const SQL_COMPARISON_WORDS = new Set(['LIKE']);
const SQL_COMPARISON_OPERATORS = new Set(['=', '!=', '<>', '<=', '>=', '<', '>']);
const SQL_LITERAL_WORDS = new Set(['TRUE', 'FALSE', 'UNKNOWN', 'NULL']);
const SQL_STACKED_WORDS = new Set(['SELECT', 'WITH', 'UNION', 'DROP', 'INSERT', 'UPDATE', 'DELETE', 'ALTER', 'CREATE', 'EXEC', 'EXECUTE', 'CALL', 'MERGE', 'TRUNCATE']);
const SQL_QUERY_CONTEXT_WORDS = new Set(['SELECT', 'FROM', 'JOIN', 'WHERE', 'DESCRIBE', 'DESC', 'EXISTS']);
const SQL_PG_CATALOGS = new Set(['pg_class', 'pg_tables', 'pg_namespace', 'pg_attribute', 'pg_database', 'pg_user']);
const SQL_MYSQL_CATALOGS = new Set(['innodb_table_stats', 'innodb_index_stats', 'user', 'db', 'tables_priv', 'columns_priv', 'proc', 'tables']);
const SQL_SERVER_CATALOGS = new Set(['tables', 'columns', 'objects', 'databases', 'schemas', 'indexes', 'all_columns']);
const ORACLE_CATALOG_SUFFIXES = new Set(['tables', 'tab_columns', 'objects', 'users', 'catalog', 'constraints', 'cons_columns', 'views']);
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

function tokenizeSqlFragment(value) {
  const text = String(value);
  const tokens = [];
  let i = 0;

  while (i < text.length && tokens.length < 1200) {
    const ch = text[i];
    if (/\s/.test(ch)) {
      i++;
      continue;
    }

    if (isSqlWordStart(ch)) {
      const start = i;
      i++;
      while (i < text.length && isSqlWordPart(text[i])) i++;
      const word = text.slice(start, i);
      tokens.push({ type: 'word', value: word, upper: word.toUpperCase() });
      continue;
    }

    if (isAsciiDigit(ch)) {
      const start = i;
      i++;
      while (i < text.length && /[0-9.]/.test(text[i])) i++;
      tokens.push({ type: 'number', value: text.slice(start, i) });
      continue;
    }

    if (ch === "'" || ch === '"' || ch === '`') {
      tokens.push({ type: 'quote', value: ch });
      i++;
      continue;
    }

    const twoChar = text.slice(i, i + 2);
    if (['!=', '<>', '<=', '>=', '||', '&&', '--'].includes(twoChar)) {
      tokens.push({ type: 'operator', value: twoChar });
      i += 2;
      continue;
    }

    if ('=<>!|&+-*/%'.includes(ch)) {
      tokens.push({ type: 'operator', value: ch });
      i++;
      continue;
    }

    if (';(),.[]{}'.includes(ch)) {
      tokens.push({ type: 'punct', value: ch });
      i++;
      continue;
    }

    i++;
  }

  return tokens;
}

function isSqlBooleanToken(token) {
  return (
    (token.type === 'word' && SQL_BOOLEAN_WORDS.has(token.upper)) ||
    (token.type === 'operator' && (token.value === '||' || token.value === '&&'))
  );
}

function isSqlComparisonToken(token) {
  return (
    (token.type === 'operator' && SQL_COMPARISON_OPERATORS.has(token.value)) ||
    (token.type === 'word' && SQL_COMPARISON_WORDS.has(token.upper))
  );
}

function isSqlValueLike(token) {
  return token && (
    token.type === 'word' ||
    token.type === 'number' ||
    token.type === 'quote' ||
    (token.type === 'punct' && token.value === ')')
  );
}

function isSqlConstantLike(token) {
  return token && (
    token.type === 'number' ||
    token.type === 'quote' ||
    (token.type === 'word' && SQL_LITERAL_WORDS.has(token.upper)) ||
    (token.type === 'punct' && token.value === ')')
  );
}

function isSqlConstantLikeAt(tokens, index) {
  const token = tokens[index];
  if (isSqlConstantLike(token)) return true;
  return token?.type === 'word' && nextToken(tokens, index)?.value === '(';
}

function previousToken(tokens, index) {
  return index > 0 ? tokens[index - 1] : null;
}

function nextToken(tokens, index) {
  return index + 1 < tokens.length ? tokens[index + 1] : null;
}

function hasSqlComparison(tokens, start, end, constantOnly = false) {
  for (let i = start; i < Math.min(tokens.length, end); i++) {
    if (!isSqlComparisonToken(tokens[i])) continue;
    const left = previousToken(tokens, i);
    const right = nextToken(tokens, i);
    if (constantOnly) {
      if (isSqlConstantLikeAt(tokens, i - 1) && isSqlConstantLikeAt(tokens, i + 1)) return true;
    } else if (isSqlValueLike(left) && isSqlValueLike(right)) {
      return true;
    }
  }
  return false;
}

function hasStrongSqlBreakoutContext(tokens, booleanIndex) {
  let quoteCount = 0;
  for (let i = 0; i < booleanIndex; i++) {
    const token = tokens[i];
    if (token.type === 'quote') quoteCount++;
    if (token.type === 'punct' && [';', ')', '('].includes(token.value)) return true;
    if (token.type === 'operator' && ['||', '&&', '--'].includes(token.value)) return true;
  }
  return (quoteCount % 2 !== 0);
}

function rightSideSqlPredicate(tokens, booleanIndex) {
  const start = booleanIndex + 1;
  const end = Math.min(tokens.length, booleanIndex + 18);
  let hasPredicate = false;
  let hasConstantPredicate = false;

  for (let i = start; i < end; i++) {
    const token = tokens[i];
    if (token.type !== 'word') continue;
    if (SQL_LITERAL_WORDS.has(token.upper)) {
      hasPredicate = true;
      hasConstantPredicate = true;
    }
    if (token.upper === 'EXISTS') {
      hasPredicate = true;
      hasConstantPredicate = true;
    }
    if (token.upper === 'BETWEEN') {
      hasPredicate = true;
      hasConstantPredicate = true;
    }
  }

  if (hasSqlComparison(tokens, start, end, true)) {
    hasPredicate = true;
    hasConstantPredicate = true;
  } else if (hasSqlComparison(tokens, start, end, false)) {
    hasPredicate = true;
  }

  return { hasPredicate, hasConstantPredicate };
}

function hasStructuralSqlBooleanAbuse(value) {
  const tokens = tokenizeSqlFragment(value);
  for (let i = 0; i < tokens.length; i++) {
    if (!isSqlBooleanToken(tokens[i])) continue;
    const right = rightSideSqlPredicate(tokens, i);
    if (!right.hasPredicate) continue;
    if (hasStrongSqlBreakoutContext(tokens, i)) return true;
  }
  return false;
}

function hasStructuralSqlStackedStatement(value) {
  const tokens = tokenizeSqlFragment(value);
  for (let i = 0; i < tokens.length; i++) {
    if (tokens[i].type !== 'punct' || tokens[i].value !== ';') continue;
    let j = i + 1;
    while (j < tokens.length && tokens[j].type === 'punct' && tokens[j].value === '(') j++;
    if (j < tokens.length && tokens[j].type === 'word' && SQL_STACKED_WORDS.has(tokens[j].upper)) return true;
  }
  return false;
}

function metadataNameAt(tokens, index) {
  if (!tokens[index] || tokens[index].type !== 'word') return null;
  const parts = [tokens[index].value.toLowerCase()];
  let end = index;
  let cursor = index + 1;

  while (
    cursor + 1 < tokens.length &&
    tokens[cursor].type === 'punct' &&
    tokens[cursor].value === '.' &&
    tokens[cursor + 1].type === 'word'
  ) {
    parts.push(tokens[cursor + 1].value.toLowerCase());
    end = cursor + 1;
    cursor += 2;
  }

  return { name: parts.join('.'), parts, end };
}

function isSqlMetadataName(nameInfo) {
  if (!nameInfo) return false;
  const { name, parts } = nameInfo;
  if (name === 'sysobjects' || name === 'sqlite_master' || name === 'sqlite_schema') return true;
  if (name === 'information_schema' || name.startsWith('information_schema.')) return true;
  if (name === 'pg_catalog' || name.startsWith('pg_catalog.') || SQL_PG_CATALOGS.has(name)) return true;
  if (parts[0] === 'sys' && SQL_SERVER_CATALOGS.has(parts[1])) return true;
  if (parts[0] === 'mysql' && SQL_MYSQL_CATALOGS.has(parts[1])) return true;
  if (['all', 'user', 'dba'].includes(parts[0]) && ORACLE_CATALOG_SUFFIXES.has(parts.slice(1).join('_'))) return true;
  for (const prefix of ['all', 'user', 'dba']) {
    const marker = `${prefix}_`;
    if (name.startsWith(marker) && ORACLE_CATALOG_SUFFIXES.has(name.slice(marker.length))) return true;
  }
  return false;
}

function isSqlQueryContext(tokens, index) {
  const token = tokens[index];
  if (!token || token.type !== 'word') return false;
  if (SQL_QUERY_CONTEXT_WORDS.has(token.upper)) return true;
  if (token.upper === 'COUNT' && nextToken(tokens, index)?.value === '(') return true;
  if (token.upper === 'SHOW') {
    const next = nextToken(tokens, index);
    const afterNext = nextToken(tokens, index + 1);
    return (
      next?.upper === 'TABLES' ||
      next?.upper === 'COLUMNS' ||
      (next?.upper === 'FULL' && (afterNext?.upper === 'TABLES' || afterNext?.upper === 'COLUMNS'))
    );
  }
  return false;
}

function hasStructuralSqlMetadataQuery(value) {
  const tokens = tokenizeSqlFragment(value);
  const queryContextIndexes = [];
  const metadataIndexes = [];

  for (let i = 0; i < tokens.length; i++) {
    if (isSqlQueryContext(tokens, i)) queryContextIndexes.push(i);
    const metadata = metadataNameAt(tokens, i);
    if (isSqlMetadataName(metadata)) {
      metadataIndexes.push(i);
      i = metadata.end;
    }
  }

  return metadataIndexes.some(metadataIndex =>
    queryContextIndexes.some(contextIndex => Math.abs(contextIndex - metadataIndex) <= 40)
  );
}

function hasRepeatedQuotedLiteralComparison(value) {
  const comparison = /(['"])([^'"]{1,80})\1\s*=\s*(['"])([^'"]{1,80})\3/g;
  let match;
  while ((match = comparison.exec(value)) !== null) {
    if (match[2] === match[4]) return true;
  }
  return false;
}

module.exports = {
  name: 'sqli',
  label: 'sqli',
  getSignals() {
    return     [
      {
        id: 'union-select',
        confidence: 0.8,
        pattern: new RegExp(unionSelectPattern(), 'i')
      },
      {
        id: 'comment-fragmented-union-select',
        confidence: 0.8,
        pattern: new RegExp(unionSelectPattern(sqlWord), 'i')
      },
      {
        id: 'union-values',
        confidence: 0.8,
        pattern: new RegExp(unionValuesPattern(), 'i')
      },
      {
        id: 'comment-fragmented-union-values',
        confidence: 0.8,
        pattern: new RegExp(unionValuesPattern(sqlWord), 'i')
      },
      {
        id: 'mysql-versioned-comment',
        confidence: 0.55,
        pattern: /(?:\/\*!\d{0,6}|MYSQL_VERSIONED_COMMENT)/i
      },
      {
        id: 'sql-structural-boolean',
        confidence: 0.75,
        test: hasStructuralSqlBooleanAbuse
      },
      {
        id: 'boolean-tautology',
        confidence: 0.75,
        pattern: new RegExp(`['"\`)]\\s*${SQL_BOOLEAN_OPERATOR}\\s+(?:NOT\\s+)?${SQL_CONSTANT_BOOLEAN_EXPRESSION}|${SQL_SYMBOL_BOOLEAN_OPERATOR}\\s+(?:NOT\\s+)?${SQL_CONSTANT_BOOLEAN_EXPRESSION}|\\b${SQL_WORD_BOOLEAN_OPERATOR}\\b\\s+(?:NOT\\s+)?${SQL_CONSTANT_BOOLEAN_EXPRESSION}|\\b\\d+\\s+\\b${SQL_WORD_BOOLEAN_OPERATOR}\\b\\s+(?:NOT\\s+)?${SQL_CONSTANT_BOOLEAN_EXPRESSION}`, 'i')
      },
      {
        id: 'drop-table',
        confidence: 0.75,
        pattern: new RegExp(`(?:^|[;\\s])DROP\\s+TABLE\\s+(?:IF\\s+EXISTS\\s+)?${SQL_IDENTIFIER}\\s*(?:CASCADE\\s*|RESTRICT\\s*)?(?:;|--|#|$)`, 'i')
      },
      {
        id: 'insert-values',
        confidence: 0.7,
        pattern: new RegExp(`\\bINSERT\\s+INTO\\s+${SQL_IDENTIFIER}\\s*(?:\\([^)]*\\)\\s*)?VALUES\\s*\\(`, 'i')
      },
      {
        id: 'update-set',
        confidence: 0.7,
        pattern: new RegExp(`\\bUPDATE\\s+${SQL_IDENTIFIER}\\s+SET\\s+${SQL_IDENTIFIER}\\s*=`, 'i')
      },
      {
        id: 'delete-from',
        confidence: 0.65,
        pattern: new RegExp(`\\bDELETE\\s+FROM\\s+${SQL_IDENTIFIER}\\s*(?:WHERE\\b|;|--|#|$)`, 'i')
      },
      {
        id: 'stacked-sql-statement',
        confidence: 0.65,
        pattern: new RegExp(`;\\s*(?:\\(\\s*)*${SQL_STACKED_STATEMENT_KEYWORD}\\b`, 'i')
      },
      {
        id: 'sql-structural-stacked-statement',
        confidence: 0.65,
        test: hasStructuralSqlStackedStatement
      },
      {
        id: 'sql-comment-breakout',
        confidence: 0.55,
        pattern: /(?:['"`]\s*(?:--|#)(?:\s|$)|--\s*$|#\s*$)/i
      },
      {
        id: 'sql-unclosed-block-comment-breakout',
        confidence: 0.55,
        pattern: /(?:['"`)]\s*\/\*(?![\s\S]*\*\/)|\/\*\s*$)/i
      },
      {
        id: 'time-delay',
        confidence: 0.75,
        pattern: /\b(?:SLEEP\s*\(|WAITFOR\s+DELAY\b|BENCHMARK\s*\(|PG_SLEEP\s*\(|DBMS_PIPE\.RECEIVE_MESSAGE\s*\()/i
      },
      {
        id: 'out-of-band',
        confidence: 0.8,
        pattern: /\b(?:LOAD_FILE\s*\(|UTL_HTTP\.REQUEST\s*\(|UTL_INADDR\.GET_HOST_ADDRESS\s*\(|INTO\s+(?:DUMP|OUT)FILE\b)/i
      },
      {
        id: 'error-based-sqli',
        confidence: 0.75,
        pattern: /\b(?:CAST\s*\(\s*(?:\(\s*SELECT\b|@@[a-z_]+)|CONVERT\s*\(\s*[a-z_]+\s*,\s*(?:\(\s*SELECT\b|@@[a-z_]+))/i
      },
      {
        id: 'nosql-operator',
        confidence: 0.65,
        pattern: /(?:^|[{,\s])["']?\$(?:where|ne|gt|lt|gte|lte|in|nin|regex|expr|or|and)["']?\s*:/i
      },
      {
        id: 'nosql-operator-key',
        confidence: 0.65,
        pattern: /^\$(?:where|ne|gt|lt|gte|lte|in|nin|regex|expr|or|and)$/i
      },
      {
        id: 'repeated-quoted-literal-comparison',
        confidence: 0.3,
        test: hasRepeatedQuotedLiteralComparison
      },
      {
        id: 'sql-metadata-probe',
        confidence: 0.45,
        pattern: new RegExp(`\\b${SQL_METADATA_OBJECT}\\b`, 'i')
      },
      {
        id: 'sql-metadata-query',
        confidence: 0.65,
        pattern: new RegExp(`\\b${SQL_METADATA_QUERY_CONTEXT}[\\s\\S]{0,240}\\b${SQL_METADATA_OBJECT}\\b|\\b${SQL_METADATA_OBJECT}\\b[\\s\\S]{0,240}\\b${SQL_METADATA_QUERY_CONTEXT}`, 'i')
      },
      {
        id: 'sql-structural-metadata-query',
        confidence: 0.65,
        test: hasStructuralSqlMetadataQuery
      }
    ];
  }
};