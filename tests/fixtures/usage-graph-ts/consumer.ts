import { format, parse } from "./util";

export function run(input: string): string {
  const value = parse(input);
  return format(value);
}
