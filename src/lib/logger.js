
export class Logger {

    constructor(log) {
        this.log = log;
    }

    Message(message) {
        if (!this.log) return;
        console.log(` [navcoin-js] ${message}`);
    }

}
