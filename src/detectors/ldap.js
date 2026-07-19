'use strict';

function hasUnbalancedParenthesesWithLdapKeywords(value) {
  const ldapKeywords = /\b(cn|uid|objectclass|memberof)\b/i;
  if (!ldapKeywords.test(value)) {
    return false;
  }
  
  let depth = 0;
  for (let i = 0; i < value.length; i++) {
    if (value[i] === '(') depth++;
    if (value[i] === ')') depth--;
    if (depth < 0) return true;
  }
  return depth !== 0;
}

module.exports = {
  name: 'ldap',
  label: 'ldap',
  getSignals() {
    return [
      {
        id: 'ldap-filter-concatenation',
        confidence: 0.8,
        pattern: /\)\s*\(/
      },
      {
        id: 'ldap-wildcard-bypass',
        confidence: 0.9,
        pattern: /\*\)\s*\(\s*objectClass\s*=\s*\*/i
      },
      {
        id: 'ldap-or-injection',
        confidence: 0.85,
        pattern: /\)\s*\(\s*\|/
      },
      {
        id: 'ldap-null-byte',
        confidence: 0.9,
        pattern: /(?:\x00|%00|\\00)/i
      },
      {
        id: 'ldap-unbalanced-parentheses',
        confidence: 0.7,
        test: hasUnbalancedParenthesesWithLdapKeywords
      }
    ];
  }
};
