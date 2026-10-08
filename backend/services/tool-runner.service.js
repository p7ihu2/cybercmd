const { spawn } = require("node:child_process");

const DEFAULT_TIMEOUT = 30_000;
const MAX_OUTPUT_SIZE = 1_000_000;

function runTool(command, args = [], options = {}) {
  const timeout = options.timeout || DEFAULT_TIMEOUT;

  return new Promise((resolve, reject) => {
    let stdout = "";
    let stderr = "";
    let finished = false;

    const child = spawn(command, args, {
      shell: false,
      windowsHide: true,
    });

    const timer = setTimeout(() => {
      if (finished) {
        return;
      }

      finished = true;
      child.kill();

      reject(new Error("Tool execution timed out."));
    }, timeout);

    child.stdout.on("data", (data) => {
      if (finished) {
        return;
      }

      stdout += data.toString();

      if (stdout.length > MAX_OUTPUT_SIZE) {
        finished = true;
        clearTimeout(timer);
        child.kill();

        reject(
          new Error("Tool output exceeded the allowed size.")
        );
      }
    });

    child.stderr.on("data", (data) => {
      if (finished) {
        return;
      }

      stderr += data.toString();

      if (stderr.length > MAX_OUTPUT_SIZE) {
        finished = true;
        clearTimeout(timer);
        child.kill();

        reject(
          new Error("Tool error output exceeded the allowed size.")
        );
      }
    });

    child.on("error", (error) => {
      if (finished) {
        return;
      }

      finished = true;
      clearTimeout(timer);

      reject(error);
    });

    child.on("close", (exitCode) => {
      if (finished) {
        return;
      }

      finished = true;
      clearTimeout(timer);

      resolve({
        stdout,
        stderr,
        exitCode,
      });
    });
  });
}

module.exports = {
  runTool,
};