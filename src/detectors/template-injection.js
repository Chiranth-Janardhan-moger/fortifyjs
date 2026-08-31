'use strict';

const DANGEROUS_SINKS = '(?:constructor|prototype|process|require|import|return\\s+this)';
const ARITHMETIC = '\\d+\\s*[+*\\-/]\\s*\\d+';

module.exports = {
  name: 'template-injection',
  label: 'template-injection',
  
  getSignals() {
    return [
      {
        id: 'ssti-dangerous-sink',
        confidence: 0.90,
        pattern: new RegExp('(?:{{|\\$\\{|<%=\\s*|#{\\s*)[^}]*?' + DANGEROUS_SINKS + '.*?(?:}}|}|%>|})', 'i')
      },
      {
        id: 'ssti-jinja-dangerous',
        confidence: 0.90,
        pattern: /\{%\s*(?:import|include)[^%]*%\}/i
      },
      {
        id: 'ssti-arithmetic-probe',
        confidence: 0.70,
        pattern: new RegExp('(?:{{|\\$\\{|<%=\\s*|#{\\s*).*?' + ARITHMETIC + '.*?(?:}}|}|%>|})')
      },
      {
        id: 'ssti-template-syntax-alone',
        confidence: 0.30,
        pattern: /(?:{{[^}]+}}|<%=[^%]+%>|#{[^}]+}|\${[^}]+})/
      }
    ];
  }
};
