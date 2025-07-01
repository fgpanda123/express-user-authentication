const fs = require('fs');
const {generateJSONSamples} = require("./util");
fs.writeFileSync('./samples/users/sample-users.json', generateJSONSamples(50));