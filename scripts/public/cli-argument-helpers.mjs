import { requireValue } from "../lib/value-validation.mjs";

export function required(value, name) {
  return requireValue(value, `Missing required --${name}`);
}

export function toCamelCase(value) {
  return value.replace(/-([a-z])/g, (_match, letter) => letter.toUpperCase());
}

export function parseCamelCaseArgs(args, usage) {
  const options = {};
  for (let index = 0; index < args.length; index += 2) {
    const key = args[index];
    const value = args[index + 1];
    if (!key?.startsWith("--") || value === undefined) {
      throw new Error(usage);
    }
    options[toCamelCase(key.slice(2))] = value;
  }
  return options;
}

export function parseLongOptionArgs(args, usage) {
  const options = {};
  for (let index = 0; index < args.length; index += 2) {
    const option = args[index];
    const value = args[index + 1];
    if (!option?.startsWith("--") || value === undefined || value.startsWith("--")) {
      throw new Error(usage);
    }
    if (options[option] !== undefined) {
      throw new Error(`${option} may only be provided once.`);
    }
    options[option] = value;
  }
  return options;
}

export function parseMappedCliArgs(argv, optionFields) {
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    if (flag === "--help" || flag === "-h") return { help: true };
    const value = argv[index + 1];
    if (value === undefined || value.startsWith("--")) {
      throw new Error(`Missing value for ${flag}.`);
    }
    if (!Object.hasOwn(optionFields, flag)) {
      throw new Error(`Unknown option: ${flag}.`);
    }
    options[optionFields[flag]] = value;
    index += 1;
  }
  return options;
}
