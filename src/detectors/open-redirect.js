'use strict';

const REDIRECT_PARAMS = [
  'redirect', 'url', 'next', 'return', 'returnUrl', 'continue', 'dest',
  'destination', 'goto', 'target', 'link', 'out', 'view', 'rurl', 
  'return_url', 'callback', 'forward'
].join('|');

module.exports = {
  name: 'open-redirect',
  label: 'open-redirect',
  
  getSignals() {
    return [
      {
        id: 'redirect-param-external-url',
        confidence: 0.75,
        pattern: new RegExp(`(?:\\?|&)(?:${REDIRECT_PARAMS})=(?:https?:)?\\/\\/[^&]+`, 'i')
      },
      {
        id: 'protocol-relative-redirect',
        confidence: 0.70,
        pattern: new RegExp(`(?:\\?|&)(?:${REDIRECT_PARAMS})=\\/\\/[a-zA-Z0-9]`, 'i')
      },
      {
        id: 'backslash-redirect',
        confidence: 0.75,
        pattern: new RegExp(`(?:\\?|&)(?:${REDIRECT_PARAMS})=(?:\\\\\\/|\\/\\\\)[a-zA-Z0-9]`, 'i')
      },
      {
        id: 'data-uri-redirect',
        confidence: 0.80,
        pattern: new RegExp(`(?:\\?|&)(?:${REDIRECT_PARAMS})=data:`, 'i')
      },
      {
        id: 'javascript-uri-redirect',
        confidence: 0.85,
        pattern: new RegExp(`(?:\\?|&)(?:${REDIRECT_PARAMS})=javascript:`, 'i')
      }
    ];
  }
};
