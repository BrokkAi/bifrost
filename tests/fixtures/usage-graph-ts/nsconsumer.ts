import * as util from "./util";

export function go(input: string): string {
  return util.format(util.parse(input));
}
