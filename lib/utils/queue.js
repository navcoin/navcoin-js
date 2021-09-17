const queue = require('queue');
const EventEmitter = require('events');

module.exports = class extends EventEmitter {
    constructor (concurrency= 4) {
        super();

        this.q = queue({concurrency: concurrency, autostart: true, results: []});
        this.count = 0;

        this.q.on('end', () => {
            this.count = 0;

            this.emit('progress', 100)
            this.emit('end')
        })

        this.q.on('success', (res, job) => {
            this.emit('progress', Math.floor((this.count-this.q.length)*100/this.count));
        })

        this.q.on('error', () => {
            this.emit('progress', Math.floor((this.count-this.q.length)*100/this.count));
        })
    }

    add(self, func, args, priority = false) {
        let jobId;

        if (priority) {
            jobId = this.q.unshift(async() => {
                try {
                    return await func.apply(self, args);
                }
                catch(e) {
                    console.log(e)
                }
            })
        } else {
            jobId = this.q.push(async() => {
                try {
                    return await func.apply(self, args);
                }
                catch(e) {
                    console.log(e)
                }
            })
        }

        this.count++;
    }
}