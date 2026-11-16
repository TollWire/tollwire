// Fixed-window counter. Simple on purpose: the monitor has one client at a time and the limits only bound the work a
// hostile local process can cause.
export class WindowLimiter {
  private windowStart = 0;
  private count = 0;

  constructor(
    private readonly max: number,
    private readonly windowMs: number,
  ) {}

  /** Counts one event; returns false if the window is already full (the event is still counted for `peek`). */
  hit(nowMs: number): boolean {
    this.roll(nowMs);
    this.count += 1;
    return this.count <= this.max;
  }

  /** True if the window is full (without counting). */
  full(nowMs: number): boolean {
    this.roll(nowMs);
    return this.count >= this.max;
  }

  /** Milliseconds until the window ends (at least 1). */
  retryAfterMs(nowMs: number): number {
    return Math.max(1, this.windowStart + this.windowMs - nowMs);
  }

  private roll(nowMs: number): void {
    if (nowMs - this.windowStart >= this.windowMs || nowMs < this.windowStart) {
      this.windowStart = nowMs;
      this.count = 0;
    }
  }
}
