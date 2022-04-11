import * as events from "events";

export default class extends events.EventEmitter {
  constructor() {
    super();

    this.list = [];
  }

  push(el) {
    this.list.push(el);
    this.emit("push");
  }
}
