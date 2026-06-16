import { Anchor } from "./Anchor";

export function render(): string {
  const anchor = new Anchor();
  return anchor.draw();
}
