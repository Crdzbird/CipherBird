import { Out } from './engine.js';

/** The object every demo's `run` receives. */
export function demoContext(engine) {
  return {
    engine,
    Out,
    call: (name, ...args) => engine.call(name, ...args),
    writeFile: (path, bytes) => engine.writeFile(path, bytes),
    readFile: (path) => engine.readFile(path),
  };
}

/** Default input values of a demo, keyed by input name. */
export function defaultInputs(demo) {
  const values = {};
  for (const input of demo.inputs || []) values[input.name] = input.value;
  return values;
}
