const fs = require('fs');

module.exports = {
  process(_sourceText, sourcePath) {
    return {
      code: `module.exports = ${JSON.stringify(fs.readFileSync(sourcePath, 'utf8'))};`,
    };
  },
};
