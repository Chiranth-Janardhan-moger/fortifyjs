'use strict';

const MONGO_OPERATORS = [
  '\\$gt', '\\$gte', '\\$lt', '\\$lte', '\\$ne', '\\$in', '\\$nin',
  '\\$or', '\\$and', '\\$not', '\\$nor', '\\$exists', '\\$type',
  '\\$expr', '\\$regex', '\\$options', '\\$text', '\\$search',
  '\\$where', '\\$all', '\\$elemMatch', '\\$size', '\\$mod',
  '\\$jsonSchema', '\\$accumulator', '\\$function'
].join('|');

const ES_OPERATORS = [
  'script', 'inline', 'painless', 'mvel', 'ctx\\._source'
].join('|');

const COUCH_OPERATORS = [
  '_design', '_view', '_find', 'map', 'reduce'
].join('|');

module.exports = {
  name: 'nosqli',
  label: 'nosqli',
  
  detectObject(obj, maxDepth = 20) {
    const signals = [];
    if (!obj || typeof obj !== 'object') return signals;
    
    function walk(node, depth) {
      if (depth > maxDepth) return;
      if (!node || typeof node !== 'object') return;
      
      if (Array.isArray(node)) {
        for (const item of node) {
          walk(item, depth + 1);
        }
        return;
      }
      
      for (const key of Object.keys(node)) {
        if (key.startsWith('$')) {
          const validOperators = [
            '$where', '$ne', '$gt', '$lt', '$gte', '$lte', '$in', '$nin', 
            '$regex', '$expr', '$or', '$and', '$jsonSchema', '$function', 
            '$accumulator', '$not', '$nor', '$exists', '$type', '$all', 
            '$elemMatch', '$size', '$mod', '$options', '$text', '$search'
          ];
          
          if (validOperators.includes(key)) {
            signals.push({
              id: 'mongo-operator-key',
              confidence: 0.80,
              label: 'nosqli'
            });
          }
        }
        
        if (key.startsWith('_design/') || key === '_view' || key === 'map' || key === 'reduce') {
          signals.push({
            id: 'couchdb-injection',
            confidence: 0.70,
            label: 'nosqli'
          });
        }
        
        if (key === 'script' && node[key] && typeof node[key] === 'object' && (node[key].inline || node[key].source)) {
           signals.push({
              id: 'es-script-injection',
              confidence: 0.80,
              label: 'nosqli'
           });
        }
        
        walk(node[key], depth + 1);
      }
    }
    
    walk(obj, 0);
    return signals;
  },

  getSignals() {
    return [
      {
        id: 'mongo-operator-value',
        confidence: 0.85,
        pattern: new RegExp(`[{,]\\s*["']?\\$(?:where|ne|gt|lt|gte|lte|in|nin|regex|expr|or|and|jsonSchema|function|accumulator)["']?\\s*:\\s*{\\s*["']?(?:${MONGO_OPERATORS})["']?\\s*:`, 'i')
      },
      {
        id: 'mongo-operator-in-string',
        confidence: 0.70,
        pattern: new RegExp(`[{,]\\s*["'](?:${MONGO_OPERATORS})["']\\s*:`, 'i')
      },
      {
        id: 'mongo-where-injection',
        confidence: 0.80,
        pattern: /(?:\$where["']?\s*:\s*["']|where\s*\(\s*["']|\$?where["']?\s*:\s*(?:function|=>))/i
      },
      {
        id: 'mongo-regex-redos',
        confidence: 0.75,
        pattern: /\$regex["']?\s*:\s*["'].*(?:\(\.\*\)|\(\.\+\)|\(\.\*|\.\+\)|\(\?.*\)|\.\*.*(?:\.\*|\.\+)|\.\+.*(?:\.\*|\.\+)|\([a-zA-Z0-9]+\+\)\+).*["']/i
      },
      {
        id: 'mongo-regex-general',
        confidence: 0.65,
        pattern: /\$regex["']?\s*:\s*["'].*[\+\*\{].*["']/i
      },
      {
        id: 'mongo-mapreduce',
        confidence: 0.75,
        pattern: /(?:mapReduce|\$function|\$accumulator)["']?\s*:\s*(?:["']?function\s*\(|{)/i
      },
      {
        id: 'mongo-aggregation-abuse',
        confidence: 0.70,
        pattern: /(?:\$lookup|\$graphLookup|\$out|\$merge|\$addFields)["']?\s*:/i
      },
      {
        id: 'mongo-jsonschema',
        confidence: 0.75,
        pattern: /(?:\$jsonSchema)["']?\s*:\s*{/i
      },
      {
        id: 'couchdb-injection',
        confidence: 0.75,
        pattern: /["']_design\/[^"']*["']\s*:\s*{|["']_view["']\s*:\s*["']/i
      },
      {
        id: 'es-script-injection',
        confidence: 0.75,
        pattern: /["']script["']\s*:\s*(?:{|["'](?:painless|mvel|inline|ctx\._source))/i
      }
    ];
  }
};
