const queue = require('queue');
const EventEmitter = require('events');

module.exports = class extends EventEmitter {
    constructor (concurrency= 4) {
        super();

        this.defaultConcurrency = concurrency;
        this.q = queue({concurrency: this.defaultConcurrency, autostart: true, results: []});
        this.count = 0;

        this.q.on('end', () => {
            this.count = 0;

            this.emit('progress', 100, this.q.length, this.count)
            this.emit('end')
        })

        this.q.on('success', (res, job) => {
            this.emit('progress', Math.floor((this.count-this.q.length)*100/this.count), this.q.length, this.count);
        })

        this.q.on('error', () => {
            this.emit('progress', Math.floor((this.count-this.q.length)*100/this.count), this.q.length, this.count);
        })
    }

    emitProgress() {
        this.emit('progress', Math.floor((this.count-this.q.length)*100/this.count), this.q.length);
    }

    add(self, func, args, priority = false, exclusive = false) {
        let jobId;

        let f = async() => {
            if (exclusive)
                this.q.concurrency = 1;
            try {
                let ret = await func.apply(self, args);
                if (exclusive)
                this.q.concurrency = this.defaultConcurrency;
                return ret;
            }
            catch(e) {
                console.log(e)
            }
        }

        if (priority) {
            jobId = this.q.unshift(f)
        } else {
            jobId = this.q.push(f)
        }

        this.count++;
    }
}