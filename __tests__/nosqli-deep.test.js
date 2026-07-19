'use strict';

const nosqli = require('../src/detectors/nosqli');

describe('NoSQL Injection Detector', () => {

  describe('Object Detection (detectObject)', () => {
    it('detects standard mongo operators in keys', () => {
      const payload = { "$gt": "1" };
      const signals = nosqli.detectObject(payload);
      expect(signals.length).toBeGreaterThan(0);
      expect(signals[0].id).toBe('mongo-operator-key');
    });

    it('detects nested mongo operators', () => {
      const payload = { "user": { "$ne": "admin" } };
      const signals = nosqli.detectObject(payload);
      expect(signals.length).toBeGreaterThan(0);
      expect(signals[0].id).toBe('mongo-operator-key');
    });

    it('does not false positive on valid dollar signs in values', () => {
      const payload = { "price": "$50.00" };
      const signals = nosqli.detectObject(payload);
      expect(signals.length).toBe(0);
    });

    it('does not false positive on unknown dollar sign keys', () => {
      const payload = { "$schema": "http://json-schema.org/draft-07/schema#" };
      const signals = nosqli.detectObject(payload);
      expect(signals.length).toBe(0);
    });

    it('detects CouchDB _design/ key', () => {
      const payload = { "_design/malicious": { "views": {} } };
      const signals = nosqli.detectObject(payload);
      expect(signals.length).toBeGreaterThan(0);
      expect(signals[0].id).toBe('couchdb-injection');
    });

    it('detects CouchDB _view key', () => {
      const payload = { "_view": "all" };
      const signals = nosqli.detectObject(payload);
      expect(signals.length).toBeGreaterThan(0);
      expect(signals[0].id).toBe('couchdb-injection');
    });

    it('detects Elasticsearch script inline', () => {
      const payload = { "script": { "inline": "ctx._source.value = 1" } };
      const signals = nosqli.detectObject(payload);
      expect(signals.length).toBeGreaterThan(0);
      expect(signals[0].id).toBe('es-script-injection');
    });
    
    it('detects Elasticsearch script source', () => {
      const payload = { "script": { "source": "Math.random()" } };
      const signals = nosqli.detectObject(payload);
      expect(signals.length).toBeGreaterThan(0);
      expect(signals[0].id).toBe('es-script-injection');
    });
  });

  describe('String Detection (getSignals)', () => {
    let signals;
    beforeAll(() => {
      signals = nosqli.getSignals();
    });

    const checkSignal = (str, signalId) => {
      let matched = false;
      for (const sig of signals) {
        if (sig.pattern.test(str)) {
          if (signalId && sig.id === signalId) matched = true;
          else if (!signalId) matched = true;
        }
      }
      return matched;
    };

    it('detects mongo operator in string', () => {
      expect(checkSignal('{"$ne": 1}', 'mongo-operator-in-string')).toBe(true);
      expect(checkSignal('{"username": {"$gt": ""}}', 'mongo-operator-in-string')).toBe(true);
    });

    it('ignores valid dollar string in string payload', () => {
      expect(checkSignal('{"price": "$50.00"}', 'mongo-operator-in-string')).toBe(false);
      expect(checkSignal('{"price": "50.00$"}', 'mongo-operator-in-string')).toBe(false);
    });

    it('detects $where injection', () => {
      expect(checkSignal('{"$where": "this.password == 1"}', 'mongo-where-injection')).toBe(true);
      expect(checkSignal('where( "return true" )', 'mongo-where-injection')).toBe(true);
      expect(checkSignal('{"$where": function() { return true; }}', 'mongo-where-injection')).toBe(true);
    });

    it('detects $regex with general pattern', () => {
      expect(checkSignal('{"$regex": ".*"}', 'mongo-regex-general')).toBe(true);
    });

    it('detects $regex with ReDoS', () => {
      expect(checkSignal('{"$regex": "(a+)+"}', 'mongo-regex-redos')).toBe(true);
      expect(checkSignal('{"$regex": ".*.*"}', 'mongo-regex-redos')).toBe(true);
    });

    it('detects mapReduce', () => {
      expect(checkSignal('{"mapReduce": function() {}}', 'mongo-mapreduce')).toBe(true);
    });

    it('detects $function', () => {
      expect(checkSignal('{"$function": { "body": "function() {}" }}', 'mongo-mapreduce')).toBe(true);
    });

    it('detects $accumulator', () => {
      expect(checkSignal('{"$accumulator": { "init": "function() {}" }}', 'mongo-mapreduce')).toBe(true);
    });

    it('detects aggregation pipeline abuse', () => {
      expect(checkSignal('{"$lookup": { "from": "users" }}', 'mongo-aggregation-abuse')).toBe(true);
      expect(checkSignal('{"$out": "backup"}', 'mongo-aggregation-abuse')).toBe(true);
    });

    it('detects $jsonSchema injection', () => {
      expect(checkSignal('{"$jsonSchema": { "required": ["username"] }}', 'mongo-jsonschema')).toBe(true);
    });

    it('detects CouchDB string patterns', () => {
      expect(checkSignal('{"_design/test": {}}', 'couchdb-injection')).toBe(true);
      expect(checkSignal('{"_view": "all"}', 'couchdb-injection')).toBe(true);
    });

    it('detects ES script injection in strings', () => {
      expect(checkSignal('{"script": { "inline": "1" }}', 'es-script-injection')).toBe(true);
      expect(checkSignal('{"script": "ctx._source"}', 'es-script-injection')).toBe(true);
    });
  });
});
