const LOCAL_TARGETS = new Set([
  "localhost",
  "127.0.0.1",
  "::1",
]);

function normalizeTarget(target) {
  if (typeof target !== "string") {
    return "";
  }

  return target.trim();
}

function isValidIPv4(target) {
  const parts = target.split(".");

  if (parts.length !== 4) {
    return false;
  }

  return parts.every((part) => {
    if (!/^\d+$/.test(part)) {
      return false;
    }

    const number = Number(part);

    return number >= 0 && number <= 255;
  });
}

function isValidHostname(target) {
  if (!target || target.length > 253) {
    return false;
  }

  const hostnameRegex =
    /^(?=.{1,253}$)(?!-)(?:[a-zA-Z0-9-]{1,63}\.)*[a-zA-Z0-9-]{1,63}$/;

  return hostnameRegex.test(target);
}

function validateTarget(target) {
  const normalized = normalizeTarget(target);

  if (!normalized) {
    return {
      valid: false,
      target: normalized,
      reason: "Target is required.",
    };
  }

  if (normalized.length > 255) {
    return {
      valid: false,
      target: normalized,
      reason: "Target is too long.",
    };
  }

  if (LOCAL_TARGETS.has(normalized.toLowerCase())) {
    return {
      valid: true,
      target: normalized,
      type: "local",
    };
  }

  if (isValidIPv4(normalized)) {
    return {
      valid: true,
      target: normalized,
      type: "ipv4",
    };
  }

  if (isValidHostname(normalized)) {
    return {
      valid: true,
      target: normalized,
      type: "hostname",
    };
  }

  return {
    valid: false,
    target: normalized,
    reason: "Invalid hostname or IPv4 address.",
  };
}

module.exports = {
  normalizeTarget,
  validateTarget,
};