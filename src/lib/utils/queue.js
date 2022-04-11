import * as queue from "queue";
import * as events from "events";

export default class extends events.EventEmitter {
  constructor(concurrency = 4) {
    super();

    this.defaultConcurrency = concurrency;
    this.q = queue.default({
      concurrency: this.defaultConcurrency,
      autostart: true,
      results: [],
    });
    this.count = 0;
    this.running = false;

    this.q.on("end", () => {
      this.count = 0;
      this.running = false;

      this.emit("progress", 100, this.q.length, this.count);
      this.emit("end");
    });

    this.q.on("success", (res, job) => {
      if (!this.running) this.emit("started");
      this.running = true;
      this.emit(
        "progress",
        Math.floor(((this.count - this.q.length) * 100) / this.count),
        this.q.length,
        this.count
      );
    });

    this.q.on("error", () => {
      this.emit(
        "progress",
        Math.floor(((this.count - this.q.length) * 100) / this.count),
        this.q.length,
        this.count
      );
    });
  }

  emitProgress() {
    this.emit(
      "progress",
      Math.floor(((this.count - this.q.length) * 100) / this.count) || 0,
      this.q.length
    );
  }

  add(self, func, args, priority = false, exclusive = false) {
    if (!this.running) this.emit("started");
    this.running = true;

    let jobId;

    let f = async () => {
      if (exclusive) this.q.concurrency = 1;
      try {
        let ret = await func.apply(self, args);
        if (exclusive) this.q.concurrency = this.defaultConcurrency;
        return ret;
      } catch (e) {
        console.log(e);
      }
    };

    if (priority) {
      jobId = this.q.unshift(f);
    } else {
      jobId = this.q.push(f);
    }

    this.count++;
  }

  stop() {
    this.q.stop();
  }
}
