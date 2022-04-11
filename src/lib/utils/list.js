import * as events from "events";

export default class extends events.EventEmitter {
  constructor() {
    super();

    this.list = [];
  }

  push(el, emit = true) {
    this.list.push(el);
    if (emit) this.emit("push");
  }
}
