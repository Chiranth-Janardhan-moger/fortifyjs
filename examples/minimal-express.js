'use strict';
const express = require('express');
const { shield } = require('../src/index');

const app = express();

app.use(shield('basic'));

app.get('/', (req, res) => res.send('FortifyJS Protected'));

if (require.main === module) {
  app.listen(3000, () => console.log('Listening on port 3000'));
}
