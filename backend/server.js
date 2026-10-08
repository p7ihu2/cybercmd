require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { spawn } = require("child_process");
const dns = require("dns").promises;
const mysql = require("mysql2/promise");

const app = express();

const PORT = Number(process.env.PORT || 5000);

const FRONTEND_URL =
  process.env.FRONTEND_URL || "http://localhost:5173";

// =========================================================
// MYSQL
// =========================================================

const pool = mysql.createPool({
  host: process.env.DB_HOST || "127.0.0.1",
  port: Number(process.env.DB_PORT || 3306),
  user: process.env.DB_USER || "cymercmd",
  password:
    process.env.DB_PASSWORD || "cymercmd_password",
  database:
    process.env.DB_NAME || "cymercmd",
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

// =========================================================
// SECURITY MIDDLEWARE
// =========================================================

app.use(
  helmet({
    crossOriginResourcePolicy: false,
  })
);

app.use(
  cors({
    origin: FRONTEND_URL,
    methods: ["GET", "POST", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type"],
  })
);

app.use(
  express.json({
    limit: "10kb",
  })
);

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: "Too many requests. Please try again later.",
  },
});

app.use("/api/", apiLimiter);

// =========================================================
// TOOL PATHS
// =========================================================

const NMAP_PATH =
  process.platform === "win32"
    ? "C:\\Program Files (x86)\\Nmap\\nmap.exe"
    : "nmap";

const CURL_PATH =
  process.platform === "win32"
    ? "curl.exe"
    : "curl";

// =========================================================
// TARGET NORMALIZATION
// =========================================================

function normalizeTarget(value) {
  if (typeof value !== "string") {
    return "";
  }

  let target = value.trim().toLowerCase();

  if (!target) {
    return "";
  }

  // Convert HTTP/HTTPS URLs to hostname.
  if (
    target.startsWith("http://") ||
    target.startsWith("https://")
  ) {
    try {
      const parsed = new URL(target);
      target = parsed.hostname;
    } catch {
      return "";
    }
  } else {
    target = target.replace(
      /^https?:\/\//i,
      ""
    );

    target = target.split("/")[0];

    // Remove port for normal hostnames.
    if (
      target.includes(":") &&
      !target.startsWith("[")
    ) {
      target = target.split(":")[0];
    }
  }

  // Remove trailing dot.
  target = target.replace(/\.$/, "");

  return target;
}

// =========================================================
// LOCAL TARGET
// =========================================================

function isLocalTarget(target) {
  const normalized = normalizeTarget(target);

  return (
    normalized === "localhost" ||
    normalized === "127.0.0.1" ||
    normalized === "::1"
  );
}

// =========================================================
// IP VALIDATION
// =========================================================

function isIPv4(target) {
  const parts = target.split(".");

  if (parts.length !== 4) {
    return false;
  }

  return parts.every((part) => {
    if (!/^\d+$/.test(part)) {
      return false;
    }

    const number = Number(part);

    return (
      number >= 0 &&
      number <= 255
    );
  });
}

function isIPv6(target) {
  return (
    target.includes(":") &&
    /^[0-9a-f:]+$/i.test(target)
  );
}

// =========================================================
// HOSTNAME VALIDATION
// =========================================================

function isValidHostname(target) {
  if (
    !target ||
    target.length > 253
  ) {
    return false;
  }

  const labels = target.split(".");

  // Hostnames such as localhost are handled
  // separately by isLocalTarget().
  if (labels.length < 2) {
    return false;
  }

  return labels.every((label) => {
    if (
      label.length < 1 ||
      label.length > 63
    ) {
      return false;
    }

    if (
      label.startsWith("-") ||
      label.endsWith("-")
    ) {
      return false;
    }

    return /^[a-z0-9-]+$/i.test(label);
  });
}

// =========================================================
// TARGET VALIDATION
// =========================================================

function isValidTarget(target) {
  const normalized = normalizeTarget(target);

  if (!normalized) {
    return false;
  }

  if (isLocalTarget(normalized)) {
    return true;
  }

  if (isIPv4(normalized)) {
    return true;
  }

  if (isIPv6(normalized)) {
    return true;
  }

  return isValidHostname(normalized);
}

// =========================================================
// TOOL EXECUTION
// =========================================================

function runTool(
  command,
  args,
  options = {}
) {
  const timeout =
    options.timeout || 30000;

  const maxOutput =
    options.maxOutput || 1024 * 1024;

  return new Promise((resolve) => {
    const started = Date.now();

    let stdout = "";
    let stderr = "";
    let timedOut = false;

    const child = spawn(
      command,
      args,
      {
        shell: false,
        windowsHide: true,
      }
    );

    const timer = setTimeout(() => {
      timedOut = true;

      try {
        child.kill();
      } catch {
        // Ignore.
      }
    }, timeout);

    child.stdout.on(
      "data",
      (data) => {
        if (stdout.length < maxOutput) {
          stdout += data.toString();

          if (stdout.length > maxOutput) {
            stdout =
              stdout.slice(0, maxOutput) +
              "\n[OUTPUT TRUNCATED]";
          }
        }
      }
    );

    child.stderr.on(
      "data",
      (data) => {
        if (stderr.length < maxOutput) {
          stderr += data.toString();

          if (stderr.length > maxOutput) {
            stderr =
              stderr.slice(0, maxOutput) +
              "\n[ERROR OUTPUT TRUNCATED]";
          }
        }
      }
    );

    child.on(
      "error",
      (error) => {
        clearTimeout(timer);

        resolve({
          success: false,
          exitCode: null,
          stdout,
          stderr:
            stderr ||
            error.message,
          timedOut,
          duration:
            (Date.now() - started) / 1000,
        });
      }
    );

    child.on(
      "close",
      (code) => {
        clearTimeout(timer);

        resolve({
          success:
            code === 0 &&
            !timedOut,
          exitCode: code,
          stdout,
          stderr,
          timedOut,
          duration:
            (Date.now() - started) / 1000,
        });
      }
    );
  });
}

// =========================================================
// DATABASE TABLES
// =========================================================

async function ensureTables() {
  await pool.execute(`
    CREATE TABLE IF NOT EXISTS scans (
      id INT AUTO_INCREMENT PRIMARY KEY,
      tool VARCHAR(100) NOT NULL,
      target VARCHAR(255) NOT NULL,
      status VARCHAR(50) NOT NULL,
      duration DECIMAL(10,3) DEFAULT 0,
      http_status INT NULL,
      open_ports INT DEFAULT 0,
      services INT DEFAULT 0,
      result LONGTEXT,
      error TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);
}

// =========================================================
// SAVE SCAN
// =========================================================

async function saveScan({
  tool,
  target,
  status,
  duration,
  httpStatus = null,
  openPorts = 0,
  services = 0,
  result = "",
  error = null,
}) {
  const [insertResult] =
    await pool.execute(
      `
        INSERT INTO scans (
          tool,
          target,
          status,
          duration,
          http_status,
          open_ports,
          services,
          result,
          error
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `,
      [
        tool,
        target,
        status,
        duration,
        httpStatus,
        openPorts,
        services,
        result,
        error,
      ]
    );

  return insertResult.insertId;
}

// =========================================================
// NMAP PARSER
// =========================================================

function parseNmapOutput(output) {
  const lines =
    String(output || "").split("\n");

  let openPorts = 0;
  let services = 0;

  for (const line of lines) {
    const trimmed = line.trim();

    if (
      /^\d+\/tcp\s+open\s+/i.test(trimmed)
    ) {
      openPorts++;
      services++;
    }
  }

  return {
    openPorts,
    services,
  };
}

// =========================================================
// HTTP STATUS PARSER
// =========================================================

function parseHttpStatus(output) {
  const match =
    String(output || "").match(
      /HTTP\/\d(?:\.\d)?\s+(\d{3})/i
    );

  return match
    ? Number(match[1])
    : null;
}

// =========================================================
// RDAP
// =========================================================

async function fetchRdap(hostname) {
  const parts = hostname.split(".");

  if (parts.length < 2) {
    throw new Error("Invalid domain.");
  }

  const tld =
    parts[parts.length - 1];

  const bootstrapResponse =
    await fetch(
      "https://data.iana.org/rdap/dns.json"
    );

  if (!bootstrapResponse.ok) {
    throw new Error(
      "Unable to retrieve RDAP bootstrap information."
    );
  }

  const bootstrap =
    await bootstrapResponse.json();

  const services =
    bootstrap.services || [];

  const service =
    services.find(
      (entry) =>
        Array.isArray(entry[0]) &&
        entry[0].some(
          (suffix) =>
            suffix.toLowerCase() ===
            tld.toLowerCase()
        )
    );

  if (
    !service ||
    !Array.isArray(service[1]) ||
    service[1].length === 0
  ) {
    throw new Error(
      `No RDAP service found for .${tld}.`
    );
  }

  const baseUrl = service[1][0];

  const rdapUrl =
    `${baseUrl.replace(/\/$/, "")}/domain/${encodeURIComponent(
      hostname
    )}`;

  const response =
    await fetch(rdapUrl, {
      headers: {
        Accept:
          "application/rdap+json, application/json",
      },
    });

  const text =
    await response.text();

  if (!response.ok) {
    throw new Error(
      `RDAP request failed with HTTP ${response.status}. ${text.slice(
        0,
        500
      )}`
    );
  }

  return text;
}

// =========================================================
// ROOT
// =========================================================

app.get("/", (req, res) => {
  res.json({
    name: "CYBERCMD",
    status: "online",
    version: "1.0.0",
  });
});

// =========================================================
// SYSTEM STATUS
// =========================================================

app.get(
  "/api/status",
  async (req, res) => {
    try {
      await pool.query("SELECT 1");

      const [rows] =
        await pool.execute(
          "SELECT COUNT(*) AS count FROM scans"
        );

      res.json({
        backend: "online",
        database: "connected",
        scanHistory:
          Number(rows[0].count),
      });
    } catch (error) {
      console.error(
        "Status check failed:",
        error
      );

      res.status(500).json({
        backend: "online",
        database: "disconnected",
        error:
          "Database connection failed.",
      });
    }
  }
);

// =========================================================
// SCAN HISTORY
// =========================================================

app.get(
  "/api/scans",
  async (req, res) => {
    try {
      const [rows] =
        await pool.execute(
          `
            SELECT
              id,
              tool,
              target,
              status,
              duration,
              http_status AS httpStatus,
              open_ports AS openPorts,
              services,
              result,
              error,
              created_at AS createdAt
            FROM scans
            ORDER BY created_at DESC
            LIMIT 500
          `
        );

      res.json({
        scans: rows,
      });
    } catch (error) {
      console.error(
        "Failed to load scans:",
        error
      );

      res.status(500).json({
        error:
          "Failed to load scan history.",
      });
    }
  }
);

app.get(
  "/api/scans/:id",
  async (req, res) => {
    try {
      const id =
        Number(req.params.id);

      if (
        !Number.isInteger(id) ||
        id <= 0
      ) {
        return res.status(400).json({
          error:
            "Invalid scan ID.",
        });
      }

      const [rows] =
        await pool.execute(
          `
            SELECT
              id,
              tool,
              target,
              status,
              duration,
              http_status AS httpStatus,
              open_ports AS openPorts,
              services,
              result,
              error,
              created_at AS createdAt
            FROM scans
            WHERE id = ?
            LIMIT 1
          `,
          [id]
        );

      if (rows.length === 0) {
        return res.status(404).json({
          error:
            "Scan not found.",
        });
      }

      res.json({
        scan: rows[0],
      });
    } catch (error) {
      console.error(
        "Failed to load scan:",
        error
      );

      res.status(500).json({
        error:
          "Failed to load scan details.",
      });
    }
  }
);

app.delete(
  "/api/scans",
  async (req, res) => {
    try {
      await pool.execute(
        "DELETE FROM scans"
      );

      res.json({
        message:
          "Scan history cleared.",
      });
    } catch (error) {
      console.error(
        "Failed to clear scans:",
        error
      );

      res.status(500).json({
        error:
          "Failed to clear scan history.",
      });
    }
  }
);

// =========================================================
// NMAP
// =========================================================

app.post(
  "/api/tools/nmap",
  async (req, res) => {
    const rawTarget =
      req.body?.target;

    const target =
      normalizeTarget(rawTarget);

    if (
      !target ||
      !isValidTarget(target)
    ) {
      return res.status(400).json({
        error:
          "Invalid target. Enter a valid domain, hostname, IPv4 address, IPv6 address, or localhost.",
      });
    }

    try {
      const execution =
        await runTool(
          NMAP_PATH,
          ["-sV", target],
          {
            timeout: 60000,
            maxOutput:
              1024 * 1024,
          }
        );

      const parsed =
        parseNmapOutput(
          execution.stdout
        );

      const status =
        execution.success
          ? "COMPLETED"
          : "FAILED";

      const result =
        execution.stdout ||
        execution.stderr;

      const scanId =
        await saveScan({
          tool: "Nmap",
          target,
          status,
          duration:
            execution.duration,
          openPorts:
            parsed.openPorts,
          services:
            parsed.services,
          result,
          error:
            execution.success
              ? null
              : execution.stderr ||
                "Nmap execution failed.",
        });

      res.status(
        execution.success
          ? 200
          : 500
      ).json({
        id: scanId,
        tool: "Nmap",
        target,
        status,
        duration:
          execution.duration,
        openPorts:
          parsed.openPorts,
        services:
          parsed.services,
        httpStatus: null,
        result,
        error:
          execution.success
            ? null
            : execution.stderr,
      });
    } catch (error) {
      console.error(
        "Nmap error:",
        error
      );

      res.status(500).json({
        error:
          "Nmap scan failed.",
      });
    }
  }
);

// =========================================================
// CURL
// =========================================================

app.post(
  "/api/tools/curl",
  async (req, res) => {
    const rawTarget =
      typeof req.body?.target ===
      "string"
        ? req.body.target.trim()
        : "";

    if (!rawTarget) {
      return res.status(400).json({
        error:
          "HTTP/HTTPS URL is required.",
      });
    }

    let parsedUrl;

    try {
      parsedUrl =
        new URL(rawTarget);
    } catch {
      return res.status(400).json({
        error:
          "Invalid URL.",
      });
    }

    if (
      parsedUrl.protocol !== "http:" &&
      parsedUrl.protocol !== "https:"
    ) {
      return res.status(400).json({
        error:
          "Only HTTP and HTTPS URLs are supported.",
      });
    }

    const hostname =
      normalizeTarget(
        parsedUrl.hostname
      );

    if (
      !hostname ||
      !isValidTarget(hostname)
    ) {
      return res.status(400).json({
        error:
          "Invalid URL hostname.",
      });
    }

    try {
      const execution =
        await runTool(
          CURL_PATH,
          [
            "-i",
            "-L",
            "--connect-timeout",
            "5",
            "--max-time",
            "15",
            "--silent",
            "--show-error",
            rawTarget,
          ],
          {
            timeout: 20000,
            maxOutput:
              1024 * 1024,
          }
        );

      const httpStatus =
        parseHttpStatus(
          execution.stdout
        );

      const status =
        execution.success
          ? "COMPLETED"
          : "FAILED";

      const result =
        execution.stdout ||
        execution.stderr;

      const scanId =
        await saveScan({
          tool: "Curl",
          target: rawTarget,
          status,
          duration:
            execution.duration,
          httpStatus,
          result,
          error:
            execution.success
              ? null
              : execution.stderr ||
                "Curl execution failed.",
        });

      res.status(
        execution.success
          ? 200
          : 500
      ).json({
        id: scanId,
        tool: "Curl",
        target: rawTarget,
        status,
        duration:
          execution.duration,
        openPorts: 0,
        services: 0,
        httpStatus,
        result,
        error:
          execution.success
            ? null
            : execution.stderr,
      });
    } catch (error) {
      console.error(
        "Curl error:",
        error
      );

      res.status(500).json({
        error:
          "Curl request failed.",
      });
    }
  }
);

// =========================================================
// DNS LOOKUP
// =========================================================

app.post(
  "/api/tools/dns",
  async (req, res) => {
    const target =
      normalizeTarget(
        req.body?.target
      );

    if (
      !target ||
      !isValidTarget(target)
    ) {
      return res.status(400).json({
        error:
          "Invalid hostname or domain.",
      });
    }

    try {
      const started = Date.now();

      const addresses =
        await dns.lookup(
          target,
          {
            all: true,
          }
        );

      const duration =
        (Date.now() - started) /
        1000;

      const result =
        JSON.stringify(
          addresses,
          null,
          2
        );

      const scanId =
        await saveScan({
          tool: "DNS Lookup",
          target,
          status: "COMPLETED",
          duration,
          result,
        });

      res.json({
        id: scanId,
        tool: "DNS Lookup",
        target,
        status: "COMPLETED",
        duration,
        openPorts: 0,
        services: 0,
        httpStatus: null,
        result,
        error: null,
      });
    } catch (error) {
      console.error(
        "DNS lookup error:",
        error
      );

      try {
        const scanId =
          await saveScan({
            tool: "DNS Lookup",
            target,
            status: "FAILED",
            duration: 0,
            result: "",
            error:
              error.message ||
              "DNS lookup failed.",
          });

        return res.status(500).json({
          id: scanId,
          tool: "DNS Lookup",
          target,
          status: "FAILED",
          duration: 0,
          openPorts: 0,
          services: 0,
          httpStatus: null,
          result: "",
          error:
            error.message ||
            "DNS lookup failed.",
        });
      } catch {
        return res.status(500).json({
          error:
            "DNS lookup failed.",
        });
      }
    }
  }
);

// =========================================================
// WHOIS / RDAP
// =========================================================

app.post(
  "/api/tools/whois",
  async (req, res) => {
    const target =
      normalizeTarget(
        req.body?.target
      );

    if (
      !target ||
      !isValidTarget(target)
    ) {
      return res.status(400).json({
        error:
          "Invalid domain.",
      });
    }

    if (
      isIPv4(target) ||
      isIPv6(target) ||
      isLocalTarget(target)
    ) {
      return res.status(400).json({
        error:
          "RDAP domain lookup requires a registered domain.",
      });
    }

    try {
      const started = Date.now();

      const result =
        await fetchRdap(target);

      const duration =
        (Date.now() - started) /
        1000;

      const scanId =
        await saveScan({
          tool: "Whois",
          target,
          status: "COMPLETED",
          duration,
          result,
        });

      res.json({
        id: scanId,
        tool: "Whois",
        target,
        status: "COMPLETED",
        duration,
        openPorts: 0,
        services: 0,
        httpStatus: null,
        result,
        error: null,
      });
    } catch (error) {
      console.error(
        "RDAP error:",
        error
      );

      try {
        const scanId =
          await saveScan({
            tool: "Whois",
            target,
            status: "FAILED",
            duration: 0,
            result: "",
            error:
              error.message ||
              "RDAP lookup failed.",
          });

        return res.status(500).json({
          id: scanId,
          tool: "Whois",
          target,
          status: "FAILED",
          duration: 0,
          openPorts: 0,
          services: 0,
          httpStatus: null,
          result: "",
          error:
            error.message ||
            "RDAP lookup failed.",
        });
      } catch {
        return res.status(500).json({
          error:
            "RDAP lookup failed.",
        });
      }
    }
  }
);

// =========================================================
// 404
// =========================================================

app.use(
  (req, res) => {
    res.status(404).json({
      error:
        "CYBERCMD API endpoint not found.",
    });
  }
);

// =========================================================
// GLOBAL ERROR HANDLER
// =========================================================

app.use(
  (error, req, res, next) => {
    console.error(
      "Unhandled server error:",
      error
    );

    res.status(500).json({
      error:
        "Internal CYBERCMD server error.",
    });
  }
);

// =========================================================
// START SERVER
// =========================================================

async function startServer() {
  try {
    await pool.query("SELECT 1");

    console.log(
      "MySQL database connected successfully."
    );

    await ensureTables();

    console.log(
      "Database tables verified."
    );

    console.log(
      "CYBERCMD target authorization: disabled"
    );

    console.log(
      "CYBERCMD tools: Nmap, Curl, DNS Lookup, Whois/RDAP"
    );

    app.listen(
      PORT,
      () => {
        console.log(
          `Server running on http://localhost:${PORT}`
        );

        console.log(
          "CYBERCMD security middleware enabled."
        );
      }
    );
  } catch (error) {
    console.error(
      "Failed to start CYBERCMD:",
      error
    );

    process.exit(1);
  }
}

startServer();