const { execSync } = require("child_process");
execSync("echo " + process.env.INPUT_TITLE); // untrusted -> shell
