'use strict';

var navcoinjs = module.exports;

// module information
navcoinjs.version = 'v' + require('./package.json').version;
navcoinjs.versionGuard = function(version) { return;
    if (version !== undefined) {
        var message = 'More than one instance of navcoin-js found. ' +
            'Please make sure to require navcoin-js and check that submodules do' +
            ' not also include their own navcoin-js dependency.';
        throw new Error(message);
    }
};
navcoinjs.versionGuard(global._navcoinjs);
global._navcoinjs = navcoinjs.version;

navcoinjs.wallet = require('./lib/wallet');
