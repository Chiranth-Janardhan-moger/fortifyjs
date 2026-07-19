const { DetectionEngine } = require('../src/index');

describe('DetectionEngine - False Positives Safety Net', () => {
  let engine;

  beforeEach(() => {
    engine = new DetectionEngine();
  });

  const checkBenign = (payload) => {
    const result = engine.detect(payload);
    expect(result.label).toBe('benign');
  };

  describe('Normal Text', () => {
    test('should allow greeting', () => checkBenign('hello world'));
    test('should allow simple sentence', () => checkBenign('This is a simple sentence'));
    test('should allow question', () => checkBenign('What time is the meeting'));
    test('should allow exclamations', () => checkBenign('Wow that is amazing'));
    test('should allow mixed casing', () => checkBenign('tHe QuIcK bRoWn FoX'));
    test('should allow numbers in text', () => checkBenign('I have 3 apples and 5 oranges'));
    test('should allow punctuation', () => checkBenign('Hello world how are you today'));
    test('should allow multi-line text', () => checkBenign('Line one and Line two and Line three'));
    test('should allow tabs', () => checkBenign('Column1 Column2 Column3'));
    test('should allow markdown', () => checkBenign('Heading bold and italic'));
    test('should allow email signatures', () => checkBenign('Best regards John Doe'));
    test('should allow dates', () => checkBenign('The date is 2023 10 25'));
    test('should allow times', () => checkBenign('The time is 14 30 00'));
    test('should allow currency amounts', () => checkBenign('The total is 50 dollars'));
    test('should allow percentages', () => checkBenign('A 100 percent improvement'));
  });

  describe('URLs/paths', () => {
    test('should allow simple domain', () => checkBenign('example.com'));
    test('should allow www domain', () => checkBenign('www.example.com'));
    test('should allow relative path', () => checkBenign('api/v1/users/profile'));
    test('should allow image path', () => checkBenign('images/photo.jpg'));
    test('should allow document path', () => checkBenign('data/files/report.pdf'));
    test('should allow html page', () => checkBenign('index.html'));
    test('should allow email address', () => checkBenign('user@example.com'));
    test('should allow asset path', () => checkBenign('assets/css/style.css'));
    test('should allow subdomain', () => checkBenign('sub.domain.co.uk/path'));
    test('should allow query string', () => checkBenign('query?search=1'));
  });

  describe('JSON', () => {
    test('should allow JSON 1', () => checkBenign('{"name": "John Doe the software engineer"}'));
    test('should allow JSON 2', () => checkBenign('{"description": "This is a benign description of the item."}'));
    test('should allow JSON 3', () => checkBenign('[{"title": "Alice in Wonderland book"}]'));
    test('should allow JSON 4', () => checkBenign('{"isActive": true, "isDeleted": false}'));
    test('should allow JSON 5', () => checkBenign('{"value": null, "other": "test string"}'));
    test('should allow JSON 6', () => checkBenign('{"data": [100, 200, 300], "count": 3}'));
    test('should allow JSON 7', () => checkBenign('{"message": "Hello world from JSON payload"}'));
    test('should allow JSON 8', () => checkBenign('{"user": {"id": 12345, "name": "Alice Smith"}}'));
  });

  describe('Search queries', () => {
    test('should allow single word search', () => checkBenign('shoes'));
    test('should allow multi-word search', () => checkBenign('running shoes for men'));
    test('should allow year in search', () => checkBenign('best running shoes 2023'));
    test('should allow natural language search', () => checkBenign('how to tie running shoes'));
    test('should allow search with numbers', () => checkBenign('top 10 running shoes 2023'));
    test('should allow search with site operator', () => checkBenign('shoes site example com'));
    test('should allow search with filetype operator', () => checkBenign('report filetype pdf'));
    test('should allow questions', () => checkBenign('where to buy cheap shoes'));
    test('should allow programming language', () => checkBenign('C plus plus programming'));
    test('should allow trending search', () => checkBenign('hashtag running today'));
  });

  describe('International text', () => {
    test('should allow Spanish text', () => checkBenign('Hola, como estas mi amigo'));
    test('should allow French text', () => checkBenign('Bonjour, comment ca va mon ami'));
    test('should allow German text', () => checkBenign('Guten Morgen, wie geht es dir heute'));
    test('should allow Chinese text', () => checkBenign('Ni hao 你好 greeting in Chinese text payload'));
    test('should allow Japanese text', () => checkBenign('Konnichiwa こんにちは greeting in Japanese payload'));
    test('should allow Arabic text', () => checkBenign('Marhaba مرحبا greeting in Arabic text payload'));
  });

  describe('Edge cases that resemble attacks', () => {
    test('should allow Irish names with apostrophe', () => checkBenign("O'Brien"));
    test('should allow SQL keyword SELECT as normal text', () => checkBenign("SELECT your plan from the list"));
    test('should allow SQL keyword UNION as normal text', () => checkBenign("The workers union voted today"));
    test('should allow SQL keyword DROP as normal text', () => checkBenign("DROP off the package at the front"));
    test('should allow word script in text', () => checkBenign("I wrote a script to automate it"));
    test('should allow price with dollar sign', () => checkBenign("The price is $50.00 today"));
    test('should allow SQL keyword OR as normal text', () => checkBenign("OR choose option B from menu"));
    test('should allow admin dashboard link', () => checkBenign("admin dashboard link is here"));
    test('should allow word INSERT as normal text', () => checkBenign("Please INSERT your card now"));
    test('should allow word UPDATE as normal text', () => checkBenign("I will UPDATE you tomorrow"));
    test('should allow word DELETE as normal text', () => checkBenign("Did you DELETE that file"));
    test('should allow math equation', () => checkBenign("math equation one plus one equals two"));
  });
});
