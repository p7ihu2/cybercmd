import { useEffect, useState } from "react";
import "./App.css";

const API_BASE = "http://localhost:5000";

const INITIAL_RESULT = "Waiting for scan...";

const TOOLS = [
  {
    name: "Nmap",
    endpoint: "/api/tools/nmap",
    description: "Network discovery and service identification",
    command: "nmap -sV",
    placeholder:
      "Enter a domain, hostname, IP address, or localhost",
  },
  {
    name: "Curl",
    endpoint: "/api/tools/curl",
    description: "HTTP response and web service inspection",
    command: "curl -i",
    placeholder: "Enter an HTTP/HTTPS URL",
  },
  {
    name: "DNS Lookup",
    endpoint: "/api/tools/dns",
    description: "Domain and hostname resolution",
    command: "dns lookup",
    placeholder: "Enter a hostname or domain",
  },
  {
    name: "Whois",
    endpoint: "/api/tools/whois",
    description: "Domain registration and RDAP information",
    command: "whois",
    placeholder: "Enter a registered domain",
  },
];

function App() {
  // =========================================================
  // SCANNER STATE
  // =========================================================

  const [target, setTarget] = useState("");
  const [selectedTool, setSelectedTool] = useState("Nmap");

  const [result, setResult] = useState(INITIAL_RESULT);
  const [loading, setLoading] = useState(false);
  const [scanStatus, setScanStatus] = useState("READY");

  const [openPorts, setOpenPorts] = useState(0);
  const [services, setServices] = useState(0);
  const [duration, setDuration] = useState(0);
  const [httpStatus, setHttpStatus] = useState(null);

  // =========================================================
  // WORKSPACE STATE
  // =========================================================

  const [activeWorkspace, setActiveWorkspace] =
    useState("scanner");

  // =========================================================
  // HISTORY STATE
  // =========================================================

  const [scanHistory, setScanHistory] = useState([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyError, setHistoryError] = useState("");

  const [selectedHistoryScan, setSelectedHistoryScan] =
    useState(null);

  const [historyDetailLoading, setHistoryDetailLoading] =
    useState(false);

  const [historyDetailError, setHistoryDetailError] =
    useState("");

  const [clearHistoryLoading, setClearHistoryLoading] =
    useState(false);

  // =========================================================
  // SYSTEM STATE
  // =========================================================

  const [backendOnline, setBackendOnline] = useState(false);
  const [databaseOnline, setDatabaseOnline] = useState(false);

  // =========================================================
  // CURRENT TOOL
  // =========================================================

  const currentTool =
    TOOLS.find(
      (tool) => tool.name === selectedTool
    ) || TOOLS[0];

  // =========================================================
  // HELPERS
  // =========================================================

  const normalizeStatus = (status) => {
    if (!status) {
      return "UNKNOWN";
    }

    return String(status)
      .trim()
      .toUpperCase();
  };

  const numberOrZero = (value) => {
    const number = Number(value);

    return Number.isFinite(number)
      ? number
      : 0;
  };

  // =========================================================
  // SAFE JSON RESPONSE
  // =========================================================

  const getResponseData = async (response) => {
    const contentType =
      response.headers.get("content-type") || "";

    if (!contentType.includes("application/json")) {
      const text = await response.text();

      throw new Error(
        text ||
          "Backend returned an invalid response."
      );
    }

    return response.json();
  };

  // =========================================================
  // RESULT PARSING
  // =========================================================

  const parseResult = (value) => {
    if (
      value === null ||
      value === undefined ||
      value === ""
    ) {
      return null;
    }

    if (typeof value !== "string") {
      return value;
    }

    try {
      return JSON.parse(value);
    } catch {
      return value;
    }
  };

  // =========================================================
  // CURL OUTPUT PARSER
  // =========================================================

  const parseCurlOutput = (value) => {
    if (!value || typeof value !== "string") {
      return {
        headers: [],
        body: "",
      };
    }

    const normalized = value.replace(/\r\n/g, "\n");

    const separatorIndex =
      normalized.indexOf("\n\n");

    if (separatorIndex === -1) {
      return {
        headers: normalized
          .split("\n")
          .filter(Boolean),
        body: "",
      };
    }

    const headerPart =
      normalized.substring(
        0,
        separatorIndex
      );

    const body =
      normalized.substring(
        separatorIndex + 2
      );

    return {
      headers: headerPart
        .split("\n")
        .filter(Boolean),
      body,
    };
  };

  // =========================================================
  // EXTRACT NMAP PORTS
  // =========================================================

  const parseNmapPorts = (value) => {
    if (!value || typeof value !== "string") {
      return [];
    }

    const lines = value
      .split(/\r?\n/)
      .map((line) => line.trim());

    const ports = [];

    for (const line of lines) {
      const match = line.match(
        /^(\d+\/(?:tcp|udp))\s+(\S+)\s+(\S+)(?:\s+(.*))?$/i
      );

      if (!match) {
        continue;
      }

      ports.push({
        port: match[1],
        state: match[2],
        service: match[3],
        version: match[4] || "",
      });
    }

    return ports;
  };

  // =========================================================
  // STRUCTURED RESULT
  // =========================================================

  const renderStructuredResult = (
    resultValue = result,
    toolName = selectedTool,
    resultTarget = target
  ) => {
    const parsed = parseResult(resultValue);

    if (
      parsed === null ||
      parsed === undefined ||
      parsed === ""
    ) {
      return (
        <div className="result-empty">
          No output available.
        </div>
      );
    }

    // -------------------------------------------------------
    // DNS LOOKUP
    // -------------------------------------------------------

    if (
      toolName === "DNS Lookup" &&
      Array.isArray(parsed)
    ) {
      const ipv4 = parsed.filter(
        (record) => Number(record.family) === 4
      );

      const ipv6 = parsed.filter(
        (record) => Number(record.family) === 6
      );

      return (
        <div className="structured-result">
          <div className="result-section-title">
            DNS RESOLUTION
          </div>

          <div className="result-grid">
            <div className="result-field">
              <span>Target</span>
              <strong>
                {resultTarget || "Unknown"}
              </strong>
            </div>

            <div className="result-field">
              <span>Total Records</span>
              <strong>
                {parsed.length}
              </strong>
            </div>

            <div className="result-field">
              <span>IPv4 Records</span>
              <strong>
                {ipv4.length}
              </strong>
            </div>

            <div className="result-field">
              <span>IPv6 Records</span>
              <strong>
                {ipv6.length}
              </strong>
            </div>
          </div>

          {ipv4.length > 0 && (
            <>
              <div className="result-section-title">
                IPv4 ADDRESSES
              </div>

              <div className="result-list">
                {ipv4.map(
                  (record, index) => (
                    <div
                      className="result-list-item"
                      key={`ipv4-${index}`}
                    >
                      <span>
                        {record.address ||
                          "Unknown"}
                      </span>

                      <strong>
                        IPv4
                      </strong>
                    </div>
                  )
                )}
              </div>
            </>
          )}

          {ipv6.length > 0 && (
            <>
              <div className="result-section-title">
                IPv6 ADDRESSES
              </div>

              <div className="result-list">
                {ipv6.map(
                  (record, index) => (
                    <div
                      className="result-list-item"
                      key={`ipv6-${index}`}
                    >
                      <span>
                        {record.address ||
                          "Unknown"}
                      </span>

                      <strong>
                        IPv6
                      </strong>
                    </div>
                  )
                )}
              </div>
            </>
          )}
        </div>
      );
    }

    // -------------------------------------------------------
    // WHOIS / RDAP
    // -------------------------------------------------------

    if (
      toolName === "Whois" &&
      typeof parsed === "object" &&
      !Array.isArray(parsed)
    ) {
      const registrationEvent =
        Array.isArray(parsed.events)
          ? parsed.events.find(
              (event) =>
                event.eventAction ===
                "registration"
            )
          : null;

      const expirationEvent =
        Array.isArray(parsed.events)
          ? parsed.events.find(
              (event) =>
                event.eventAction ===
                "expiration"
            )
          : null;

      const registrarEntity =
        Array.isArray(parsed.entities)
          ? parsed.entities.find(
              (entity) =>
                Array.isArray(
                  entity.roles
                ) &&
                entity.roles.includes(
                  "registrar"
                )
            )
          : null;

      let registrarName = "N/A";

      if (
        registrarEntity?.vcardArray &&
        Array.isArray(
          registrarEntity.vcardArray[1]
        )
      ) {
        const fnRecord =
          registrarEntity.vcardArray[1].find(
            (item) =>
              item[0] === "fn"
          );

        if (fnRecord?.[3]) {
          registrarName = fnRecord[3];
        }
      }

      const nameservers =
        Array.isArray(parsed.nameservers)
          ? parsed.nameservers
          : [];

      const statuses =
        Array.isArray(parsed.status)
          ? parsed.status
          : [];

      return (
        <div className="structured-result">
          <div className="result-section-title">
            DOMAIN INFORMATION
          </div>

          <div className="result-grid">
            <div className="result-field">
              <span>Domain</span>

              <strong>
                {parsed.ldhName ||
                  parsed.unicodeName ||
                  resultTarget ||
                  "N/A"}
              </strong>
            </div>

            <div className="result-field">
              <span>Registrar</span>

              <strong>
                {registrarName}
              </strong>
            </div>

            <div className="result-field">
              <span>Registration</span>

              <strong>
                {registrationEvent?.eventDate ||
                  "N/A"}
              </strong>
            </div>

            <div className="result-field">
              <span>Expiration</span>

              <strong>
                {expirationEvent?.eventDate ||
                  "N/A"}
              </strong>
            </div>
          </div>

          <div className="result-section-title">
            DOMAIN STATUS
          </div>

          {statuses.length > 0 ? (
            <div className="result-tags">
              {statuses.map(
                (status, index) => (
                  <span
                    className="result-tag"
                    key={`${status}-${index}`}
                  >
                    {status}
                  </span>
                )
              )}
            </div>
          ) : (
            <div className="result-empty">
              No domain status information.
            </div>
          )}

          <div className="result-section-title">
            NAMESERVERS
          </div>

          {nameservers.length > 0 ? (
            <div className="result-list">
              {nameservers.map(
                (server, index) => (
                  <div
                    className="result-list-item"
                    key={
                      server.ldhName ||
                      server.unicodeName ||
                      index
                    }
                  >
                    {server.ldhName ||
                      server.unicodeName ||
                      "Unknown"}
                  </div>
                )
              )}
            </div>
          ) : (
            <div className="result-empty">
              No nameserver information.
            </div>
          )}
        </div>
      );
    }

    // -------------------------------------------------------
    // NMAP
    // -------------------------------------------------------

    if (
      toolName === "Nmap" &&
      typeof parsed === "string"
    ) {
      const ports =
        parseNmapPorts(parsed);

      return (
        <div className="structured-result">
          <div className="result-section-title">
            NETWORK SCAN
          </div>

          <div className="result-grid">
            <div className="result-field">
              <span>Target</span>

              <strong>
                {resultTarget || "Unknown"}
              </strong>
            </div>

            <div className="result-field">
              <span>Open Ports</span>

              <strong>
                {openPorts}
              </strong>
            </div>

            <div className="result-field">
              <span>Services</span>

              <strong>
                {services}
              </strong>
            </div>

            <div className="result-field">
              <span>Duration</span>

              <strong>
                {duration}s
              </strong>
            </div>
          </div>

          {ports.length > 0 ? (
            <>
              <div className="result-section-title">
                DETECTED SERVICES
              </div>

              <div className="result-table">
                <div className="result-table-header">
                  <span>PORT</span>
                  <span>STATE</span>
                  <span>SERVICE</span>
                  <span>VERSION</span>
                </div>

                {ports.map(
                  (port, index) => (
                    <div
                      className="result-table-row"
                      key={`${port.port}-${index}`}
                    >
                      <span>
                        {port.port}
                      </span>

                      <span>
                        {port.state}
                      </span>

                      <span>
                        {port.service}
                      </span>

                      <span>
                        {port.version ||
                          "N/A"}
                      </span>
                    </div>
                  )
                )}
              </div>
            </>
          ) : (
            <div className="result-empty">
              No structured port information
              detected in the command output.
            </div>
          )}
        </div>
      );
    }

    // -------------------------------------------------------
    // CURL
    // -------------------------------------------------------

    if (
      toolName === "Curl" &&
      typeof parsed === "string"
    ) {
      const curl =
        parseCurlOutput(parsed);

      const headerLines =
        curl.headers.filter(
          (line) =>
            !line.startsWith("HTTP/")
        );

      return (
        <div className="structured-result">
          <div className="result-section-title">
            HTTP RESPONSE
          </div>

          <div className="result-grid">
            <div className="result-field">
              <span>Target</span>

              <strong>
                {resultTarget || "Unknown"}
              </strong>
            </div>

            <div className="result-field">
              <span>HTTP Status</span>

              <strong>
                {httpStatus !== null
                  ? httpStatus
                  : "N/A"}
              </strong>
            </div>

            <div className="result-field">
              <span>Duration</span>

              <strong>
                {duration}s
              </strong>
            </div>

            <div className="result-field">
              <span>Headers</span>

              <strong>
                {headerLines.length}
              </strong>
            </div>
          </div>

          {curl.headers.length > 0 && (
            <>
              <div className="result-section-title">
                RESPONSE HEADERS
              </div>

              <div className="result-list">
                {curl.headers.map(
                  (header, index) => (
                    <div
                      className="result-list-item result-header-item"
                      key={index}
                    >
                      {header}
                    </div>
                  )
                )}
              </div>
            </>
          )}

          {curl.body && (
            <>
              <div className="result-section-title">
                RESPONSE BODY
              </div>

              <pre className="structured-body">
                {curl.body}
              </pre>
            </>
          )}
        </div>
      );
    }

    // -------------------------------------------------------
    // GENERIC JSON OBJECT
    // -------------------------------------------------------

    if (
      typeof parsed === "object" &&
      !Array.isArray(parsed)
    ) {
      return (
        <div className="structured-result">
          <div className="result-section-title">
            RESULT DATA
          </div>

          <div className="result-list">
            {Object.entries(parsed).map(
              ([key, value]) => (
                <div
                  className="result-list-item"
                  key={key}
                >
                  <span>
                    {key}
                  </span>

                  <strong>
                    {typeof value ===
                    "object"
                      ? JSON.stringify(
                          value
                        )
                      : String(value)}
                  </strong>
                </div>
              )
            )}
          </div>
        </div>
      );
    }

    // -------------------------------------------------------
    // FALLBACK
    // -------------------------------------------------------

    return (
      <div className="structured-result">
        <div className="result-section-title">
          TOOL OUTPUT
        </div>

        <pre className="raw-result">
          {String(parsed)}
        </pre>
      </div>
    );
  };

  // =========================================================
  // CHECK BACKEND
  // =========================================================

  const checkBackend = async () => {
    try {
      const response = await fetch(
        `${API_BASE}/api/status`
      );

      const data =
        await getResponseData(response);

      if (!response.ok) {
        setBackendOnline(false);
        setDatabaseOnline(false);
        return;
      }

      setBackendOnline(true);

      setDatabaseOnline(
        data.database === "connected"
      );
    } catch (error) {
      console.error(
        "Backend status check failed:",
        error
      );

      setBackendOnline(false);
      setDatabaseOnline(false);
    }
  };

  // =========================================================
  // LOAD SCAN HISTORY
  // =========================================================

  const loadHistory = async () => {
    setHistoryLoading(true);
    setHistoryError("");

    try {
      const response = await fetch(
        `${API_BASE}/api/scans`
      );

      const data =
        await getResponseData(response);

      if (!response.ok) {
        throw new Error(
          data.error ||
            data.message ||
            "Failed to load scan history."
        );
      }

      const scans = Array.isArray(
        data.scans
      )
        ? data.scans
        : [];

      setScanHistory(scans);
      setBackendOnline(true);
    } catch (error) {
      console.error(
        "Failed to load scan history:",
        error
      );

      setHistoryError(
        error.message ||
          "Could not load scan history."
      );
    } finally {
      setHistoryLoading(false);
    }
  };

  // =========================================================
  // INITIAL APPLICATION LOAD
  // =========================================================

  useEffect(() => {
    checkBackend();
    loadHistory();
  }, []);

  // =========================================================
  // RESET CURRENT SCAN
  // =========================================================

  const resetScan = () => {
    setTarget("");
    setResult(INITIAL_RESULT);
    setScanStatus("READY");

    setOpenPorts(0);
    setServices(0);
    setDuration(0);
    setHttpStatus(null);

    setLoading(false);

    setSelectedHistoryScan(null);
    setHistoryDetailError("");
  };

  // =========================================================
  // RUN SECURITY TOOL
  // =========================================================

  const runScan = async () => {
    const cleanTarget =
      target.trim();

    if (!cleanTarget) {
      setResult(
        "Please enter a valid target."
      );

      setScanStatus("FAILED");

      return;
    }

    if (loading) {
      return;
    }

    setLoading(true);
    setScanStatus("SCANNING");

    setResult(
      `Starting ${selectedTool}...`
    );

    setOpenPorts(0);
    setServices(0);
    setDuration(0);
    setHttpStatus(null);

    setSelectedHistoryScan(null);
    setHistoryDetailError("");

    try {
      const response = await fetch(
        `${API_BASE}${currentTool.endpoint}`,
        {
          method: "POST",

          headers: {
            "Content-Type":
              "application/json",
          },

          body: JSON.stringify({
            target: cleanTarget,
          }),
        }
      );

      const data =
        await getResponseData(response);

      if (!response.ok) {
        throw new Error(
          data.error ||
            data.message ||
            "Tool execution failed."
        );
      }

      const normalizedStatus =
        normalizeStatus(
          data.status
        );

      setResult(
        data.result ||
          "Tool completed but returned no output."
      );

      setScanStatus(
        normalizedStatus
      );

      setOpenPorts(
        numberOrZero(
          data.openPorts
        )
      );

      setServices(
        numberOrZero(
          data.services
        )
      );

      setDuration(
        numberOrZero(
          data.duration
        )
      );

      setHttpStatus(
        data.httpStatus !== null &&
        data.httpStatus !== undefined &&
        data.httpStatus !== ""
          ? data.httpStatus
          : null
      );

      setBackendOnline(true);

      await loadHistory();
    } catch (error) {
      console.error(
        "CYBERCMD scan error:",
        error
      );

      const errorMessage =
        error.message ||
        "Could not connect to backend.";

      setScanStatus("FAILED");
      setResult(errorMessage);

      if (
        errorMessage
          .toLowerCase()
          .includes("failed to fetch")
      ) {
        setBackendOnline(false);
        setDatabaseOnline(false);
      }
    } finally {
      setLoading(false);
    }
  };

  // =========================================================
  // OPEN HISTORY ITEM
  // =========================================================

  const openHistoryItem = async (
    item
  ) => {
    if (!item || !item.id) {
      return;
    }

    setActiveWorkspace(
      "history"
    );

    setHistoryDetailLoading(
      true
    );

    setHistoryDetailError("");

    try {
      const response = await fetch(
        `${API_BASE}/api/scans/${item.id}`
      );

      const data =
        await getResponseData(response);

      if (!response.ok) {
        throw new Error(
          data.error ||
            data.message ||
            "Failed to load scan details."
        );
      }

      if (!data.scan) {
        throw new Error(
          "Scan details were not returned by the backend."
        );
      }

      setSelectedHistoryScan(
        data.scan
      );

      setBackendOnline(true);
    } catch (error) {
      console.error(
        "Failed to load scan details:",
        error
      );

      setHistoryDetailError(
        error.message ||
          "Could not load scan details."
      );

      setSelectedHistoryScan(null);
    } finally {
      setHistoryDetailLoading(
        false
      );
    }
  };

  // =========================================================
  // LOAD HISTORY SCAN INTO SCANNER
  // =========================================================

  const useHistoryScan = (
    scan
  ) => {
    if (!scan) {
      return;
    }

    const historyTool =
      String(
        scan.tool || ""
      ).trim();

    const matchingTool =
      TOOLS.find(
        (tool) =>
          tool.name.toLowerCase() ===
          historyTool.toLowerCase()
      );

    if (matchingTool) {
      setSelectedTool(
        matchingTool.name
      );
    }

    setTarget(
      scan.target || ""
    );

    setScanStatus(
      normalizeStatus(
        scan.status
      )
    );

    setDuration(
      numberOrZero(
        scan.duration
      )
    );

    setOpenPorts(
      numberOrZero(
        scan.openPorts
      )
    );

    setServices(
      numberOrZero(
        scan.services
      )
    );

    setHttpStatus(
      scan.httpStatus !== null &&
      scan.httpStatus !== undefined &&
      scan.httpStatus !== ""
        ? scan.httpStatus
        : null
    );

    setResult(
      scan.result ||
        scan.error ||
        "No saved output."
    );

    setSelectedHistoryScan(
      scan
    );

    setHistoryDetailError("");

    setActiveWorkspace(
      "scanner"
    );
  };

  // =========================================================
  // CLEAR ALL HISTORY
  // =========================================================

  const clearScanHistory =
    async () => {
      if (clearHistoryLoading) {
        return;
      }

      const confirmed =
        window.confirm(
          "Are you sure you want to clear all scan history?\n\nThis will permanently delete all saved scan records."
        );

      if (!confirmed) {
        return;
      }

      setClearHistoryLoading(
        true
      );

      setHistoryError("");

      try {
        const response = await fetch(
          `${API_BASE}/api/scans`,
          {
            method: "DELETE",
          }
        );

        const data =
          await getResponseData(
            response
          );

        if (!response.ok) {
          throw new Error(
            data.error ||
              data.message ||
              "Failed to clear scan history."
          );
        }

        setScanHistory([]);
        setSelectedHistoryScan(
          null
        );
        setHistoryDetailError("");

        setBackendOnline(true);
        setDatabaseOnline(true);
      } catch (error) {
        console.error(
          "Clear history error:",
          error
        );

        setHistoryError(
          error.message ||
            "Failed to clear scan history."
        );
      } finally {
        setClearHistoryLoading(
          false
        );
      }
    };

  // =========================================================
  // SELECT TOOL
  // =========================================================

  const selectTool = (
    toolName
  ) => {
    const tool =
      TOOLS.find(
        (item) =>
          item.name ===
          toolName
      ) || TOOLS[0];

    setSelectedTool(
      tool.name
    );

    setActiveWorkspace(
      "scanner"
    );

    resetScan();
  };

  // =========================================================
  // SCANNER PAGE
  // =========================================================

  const renderScanner =
    () => {
      return (
        <>
          <section className="target-panel">
            <div className="panel-title">
              <div>
                <div className="eyebrow">
                  TARGET CONFIGURATION
                </div>

                <h3>
                  Scan Target
                </h3>
              </div>
            </div>

            <div className="target-row">
              <input
                type="text"
                placeholder={
                  currentTool.placeholder
                }
                value={target}
                disabled={loading}
                onChange={(
                  event
                ) =>
                  setTarget(
                    event.target.value
                  )
                }
                onKeyDown={(
                  event
                ) => {
                  if (
                    event.key ===
                      "Enter" &&
                    !loading
                  ) {
                    runScan();
                  }
                }}
              />

              <button
                className="scan-button"
                onClick={
                  runScan
                }
                disabled={
                  loading ||
                  !target.trim()
                }
              >
                {loading
                  ? "SCANNING..."
                  : `RUN ${selectedTool.toUpperCase()}`}
              </button>

              <button
                className="reset-button"
                onClick={
                  resetScan
                }
                disabled={
                  loading
                }
              >
                RESET
              </button>
            </div>
          </section>

          <section className="overview-grid">
            <div className="panel tool-card">
              <div className="card-header">
                <div className="eyebrow">
                  SELECTED TOOL
                </div>

                <div className="tool-status">
                  {loading
                    ? "RUNNING"
                    : "READY"}
                </div>
              </div>

              <div className="tool-main">
                <div className="tool-icon">
                  {selectedTool.charAt(
                    0
                  )}
                </div>

                <div>
                  <h3>
                    {selectedTool}
                  </h3>

                  <p>
                    {
                      currentTool.description
                    }
                  </p>
                </div>
              </div>
            </div>

            <div className="panel info-card">
              <div className="card-header">
                <div className="eyebrow">
                  SCAN INFORMATION
                </div>

                <div className="tool-status">
                  {scanStatus}
                </div>
              </div>

              <div className="info-grid">
                <div>
                  <span>
                    Target
                  </span>

                  <strong>
                    {target ||
                      "No target"}
                  </strong>
                </div>

                <div>
                  <span>
                    Status
                  </span>

                  <strong className="scanning">
                    {scanStatus}
                  </strong>
                </div>

                <div>
                  <span>
                    Open Ports
                  </span>

                  <strong>
                    {openPorts}
                  </strong>
                </div>

                <div>
                  <span>
                    Services
                  </span>

                  <strong>
                    {services}
                  </strong>
                </div>

                <div>
                  <span>
                    Duration
                  </span>

                  <strong>
                    {duration}s
                  </strong>
                </div>

                <div>
                  <span>
                    Tool
                  </span>

                  <strong>
                    {selectedTool}
                  </strong>
                </div>

                {httpStatus !==
                  null && (
                  <div>
                    <span>
                      HTTP Status
                    </span>

                    <strong>
                      {
                        httpStatus
                      }
                    </strong>
                  </div>
                )}
              </div>
            </div>
          </section>

          <section className="panel terminal-panel">
            <div className="terminal-header">
              <div>
                <div className="eyebrow">
                  SCAN RESULTS
                </div>

                <h3>
                  Structured Security Results
                </h3>
              </div>

              <div className="terminal-status">
                ● {scanStatus}
              </div>
            </div>

            <div className="terminal">
              <div className="terminal-command">
                <span>
                  $
                </span>{" "}
                {
                  currentTool.command
                }{" "}
                {target ||
                  "target"}
              </div>

              <div className="terminal-meta">
                Target:{" "}
                {target ||
                  "none"}
                <br />
                Tool:{" "}
                {selectedTool}
                <br />
                Status:{" "}
                {scanStatus}
              </div>

              {renderStructuredResult(
                result,
                selectedTool,
                target
              )}

              <div className="raw-output-section">
                <div className="result-section-title">
                  RAW COMMAND OUTPUT
                </div>

                <pre className="raw-result">
                  {result}
                </pre>
              </div>
            </div>
          </section>
        </>
      );
    };

  // =========================================================
  // HISTORY DETAILS
  // =========================================================

  const renderHistoryDetails =
    () => {
      if (
        historyDetailLoading
      ) {
        return (
          <div className="empty-inline">
            Loading scan details...
          </div>
        );
      }

      if (
        historyDetailError
      ) {
        return (
          <div className="empty-inline">
            {
              historyDetailError
            }
          </div>
        );
      }

      if (
        !selectedHistoryScan
      ) {
        return (
          <div className="empty-inline">
            Select a scan from the history list to view its details.
          </div>
        );
      }

      const scan =
        selectedHistoryScan;

      return (
        <div className="history-detail">
          <div className="history-detail-header">
            <div>
              <div className="eyebrow">
                SCAN DETAILS
              </div>

              <h3>
                {scan.tool ||
                  "Unknown Tool"}
              </h3>

              <p>
                {scan.target ||
                  "Unknown target"}
              </p>
            </div>

            <div className="history-detail-actions">
              <span className="history-status">
                {normalizeStatus(
                  scan.status
                )}
              </span>

              <button
                className="scan-button"
                onClick={() =>
                  useHistoryScan(
                    scan
                  )
                }
              >
                OPEN IN SCANNER
              </button>
            </div>
          </div>

          <div className="info-grid history-info-grid">
            <div>
              <span>
                Scan ID
              </span>

              <strong>
                #{scan.id}
              </strong>
            </div>

            <div>
              <span>
                Tool
              </span>

              <strong>
                {scan.tool ||
                  "Unknown"}
              </strong>
            </div>

            <div>
              <span>
                Target
              </span>

              <strong>
                {scan.target ||
                  "Unknown"}
              </strong>
            </div>

            <div>
              <span>
                Status
              </span>

              <strong>
                {normalizeStatus(
                  scan.status
                )}
              </strong>
            </div>

            <div>
              <span>
                Duration
              </span>

              <strong>
                {numberOrZero(
                  scan.duration
                )}
                s
              </strong>
            </div>

            <div>
              <span>
                Open Ports
              </span>

              <strong>
                {numberOrZero(
                  scan.openPorts
                )}
              </strong>
            </div>

            <div>
              <span>
                Services
              </span>

              <strong>
                {numberOrZero(
                  scan.services
                )}
              </strong>
            </div>

            {scan.httpStatus !==
              null &&
              scan.httpStatus !==
                undefined && (
                <div>
                  <span>
                    HTTP Status
                  </span>

                  <strong>
                    {
                      scan.httpStatus
                    }
                  </strong>
                </div>
              )}

            <div>
              <span>
                Created
              </span>

              <strong>
                {scan.createdAt
                  ? new Date(
                      scan.createdAt
                    ).toLocaleString()
                  : "Unknown"}
              </strong>
            </div>
          </div>

          <div className="panel report-panel">
            <div className="card-header">
              <div className="eyebrow">
                STRUCTURED RESULT
              </div>

              <div className="tool-status">
                RECORD #
                {scan.id}
              </div>
            </div>

            {renderStructuredResult(
              scan.result ||
                scan.error ||
                "No saved output.",
              scan.tool ||
                "Unknown",
              scan.target ||
                ""
            )}
          </div>

          <div className="panel report-panel">
            <div className="card-header">
              <div className="eyebrow">
                SAVED COMMAND OUTPUT
              </div>

              <div className="tool-status">
                RECORD #
                {scan.id}
              </div>
            </div>

            <div className="terminal history-terminal">
              <pre className="raw-result">
                {scan.result ||
                  scan.error ||
                  "No saved output."}
              </pre>
            </div>
          </div>

          {scan.error && (
            <div className="empty-inline">
              Error:{" "}
              {scan.error}
            </div>
          )}
        </div>
      );
    };

  // =========================================================
  // HISTORY PAGE
  // =========================================================

  const renderHistory =
    () => {
      return (
        <section className="workspace-page">
          <div className="page-header">
            <div>
              <div className="eyebrow">
                WORKSPACE
              </div>

              <h2>
                Scan History
              </h2>

              <p>
                Persistent security assessment records
              </p>
            </div>

            <div className="page-actions">
              <button
                className="reset-button"
                onClick={
                  loadHistory
                }
                disabled={
                  historyLoading ||
                  clearHistoryLoading
                }
              >
                {historyLoading
                  ? "LOADING..."
                  : "REFRESH"}
              </button>

              <button
                className="reset-button"
                onClick={
                  clearScanHistory
                }
                disabled={
                  historyLoading ||
                  clearHistoryLoading ||
                  scanHistory.length ===
                    0
                }
              >
                {clearHistoryLoading
                  ? "CLEARING..."
                  : "CLEAR HISTORY"}
              </button>
            </div>
          </div>

          {historyError && (
            <div className="empty-state">
              <h3>
                Could not load history
              </h3>

              <p>
                {historyError}
              </p>

              <button
                className="scan-button"
                onClick={
                  loadHistory
                }
                disabled={
                  historyLoading
                }
              >
                TRY AGAIN
              </button>
            </div>
          )}

          {!historyError &&
            historyLoading &&
            scanHistory.length ===
              0 && (
              <div className="empty-state">
                <h3>
                  Loading scan history...
                </h3>
              </div>
            )}

          {!historyError &&
            !historyLoading &&
            scanHistory.length ===
              0 && (
              <div className="empty-state">
                <div className="empty-icon">
                  H
                </div>

                <h3>
                  No scan history
                </h3>

                <p>
                  Completed and failed scan records will appear here.
                </p>

                <button
                  className="scan-button"
                  onClick={() =>
                    setActiveWorkspace(
                      "scanner"
                    )
                  }
                >
                  START SCAN
                </button>
              </div>
            )}

          {!historyError &&
            scanHistory.length >
              0 && (
              <div className="history-layout">
                <div className="history-list">
                  {scanHistory.map(
                    (item) => (
                      <button
                        key={
                          item.id
                        }
                        className={`history-item ${
                          selectedHistoryScan?.id ===
                          item.id
                            ? "selected"
                            : ""
                        }`}
                        onClick={() =>
                          openHistoryItem(
                            item
                          )
                        }
                      >
                        <div className="history-tool">
                          <span className="tool-icon-small">
                            {String(
                              item.tool ||
                                "?"
                            ).charAt(
                              0
                            )}
                          </span>

                          <div>
                            <strong>
                              {item.tool ||
                                "Unknown tool"}
                            </strong>

                            <span>
                              {item.target ||
                                "Unknown target"}
                            </span>
                          </div>
                        </div>

                        <div className="history-details">
                          <span>
                            {item.createdAt
                              ? new Date(
                                  item.createdAt
                                ).toLocaleString()
                              : "Unknown time"}
                          </span>

                          <span>
                            {numberOrZero(
                              item.duration
                            )}
                            s
                          </span>

                          <span className="history-status">
                            {normalizeStatus(
                              item.status
                            )}
                          </span>
                        </div>
                      </button>
                    )
                  )}
                </div>

                <div className="panel history-details-panel">
                  {renderHistoryDetails()}
                </div>
              </div>
            )}
        </section>
      );
    };

  // =========================================================
  // REPORTS PAGE
  // =========================================================

  const renderReports =
    () => {
      const successfulScans =
        scanHistory.filter(
          (item) =>
            normalizeStatus(
              item.status
            ) === "COMPLETED"
        ).length;

      const failedScans =
        scanHistory.filter(
          (item) =>
            normalizeStatus(
              item.status
            ) === "FAILED"
        ).length;

      const toolsUsed =
        new Set(
          scanHistory
            .map((item) =>
              String(
                item.tool || ""
              ).trim()
            )
            .filter(Boolean)
        ).size;

      return (
        <section className="workspace-page">
          <div className="page-header">
            <div>
              <div className="eyebrow">
                WORKSPACE
              </div>

              <h2>
                Reports
              </h2>

              <p>
                Persistent security assessment results
              </p>
            </div>

            <div className="page-actions">
              <button
                className="reset-button"
                onClick={
                  loadHistory
                }
                disabled={
                  historyLoading
                }
              >
                {historyLoading
                  ? "LOADING..."
                  : "REFRESH"}
              </button>
            </div>
          </div>

          <div className="report-summary">
            <div className="report-card">
              <span>
                TOTAL SCANS
              </span>

              <strong>
                {scanHistory.length}
              </strong>
            </div>

            <div className="report-card">
              <span>
                TOOLS USED
              </span>

              <strong>
                {toolsUsed}
              </strong>
            </div>

            <div className="report-card">
              <span>
                COMPLETED
              </span>

              <strong>
                {successfulScans}
              </strong>
            </div>

            <div className="report-card">
              <span>
                FAILED
              </span>

              <strong>
                {failedScans}
              </strong>
            </div>
          </div>

          <div className="panel report-panel">
            <div className="card-header">
              <div className="eyebrow">
                SCAN RECORDS
              </div>

              <div className="tool-status">
                {scanHistory.length}{" "}
                RECORDS
              </div>
            </div>

            {scanHistory.length ===
            0 ? (
              <div className="empty-inline">
                No reports available yet.
              </div>
            ) : (
              <div className="report-list">
                {scanHistory.map(
                  (item) => (
                    <button
                      className="report-row"
                      key={
                        item.id
                      }
                      onClick={() =>
                        openHistoryItem(
                          item
                        )
                      }
                    >
                      <div>
                        <strong>
                          {item.tool ||
                            "Unknown tool"}
                        </strong>

                        <span>
                          {item.target ||
                            "Unknown target"}
                        </span>
                      </div>

                      <div>
                        <span>
                          {item.createdAt
                            ? new Date(
                                item.createdAt
                              ).toLocaleString()
                            : "Unknown time"}
                        </span>

                        <span>
                          {normalizeStatus(
                            item.status
                          )}
                        </span>
                      </div>
                    </button>
                  )
                )}
              </div>
            )}
          </div>
        </section>
      );
    };

  // =========================================================
  // SETTINGS PAGE
  // =========================================================

  const renderSettings =
    () => {
      return (
        <section className="workspace-page">
          <div className="page-header">
            <div>
              <div className="eyebrow">
                CONFIGURATION
              </div>

              <h2>
                Settings
              </h2>

              <p>
                CYBERCMD system configuration
              </p>
            </div>

            <div className="page-actions">
              <button
                className="reset-button"
                onClick={() => {
                  checkBackend();
                  loadHistory();
                }}
              >
                REFRESH
              </button>
            </div>
          </div>

          <div className="settings-grid">
            <div className="panel setting-card">
              <div className="eyebrow">
                BACKEND
              </div>

              <h3>
                Backend Connection
              </h3>

              <p>
                Node.js / Express API
              </p>

              <span className="setting-status">
                ●{" "}
                {backendOnline
                  ? "ONLINE"
                  : "OFFLINE"}
              </span>
            </div>

            <div className="panel setting-card">
              <div className="eyebrow">
                DATABASE
              </div>

              <h3>
                MySQL Persistence
              </h3>

              <p>
                Scan records are persisted in MySQL.
              </p>

              <span className="setting-status">
                ●{" "}
                {databaseOnline
                  ? "CONNECTED"
                  : "UNAVAILABLE"}
              </span>
            </div>

            <div className="panel setting-card">
              <div className="eyebrow">
                TARGET INPUT
              </div>

              <h3>
                Flexible Targeting
              </h3>

              <p>
                Enter a valid domain, hostname, IP address, or URL depending on the selected tool.
              </p>

              <span className="setting-status">
                READY
              </span>
            </div>

            <div className="panel setting-card">
              <div className="eyebrow">
                AVAILABLE TOOLS
              </div>

              <h3>
                Tool Integrations
              </h3>

              <p>
                Security tools currently integrated into CYBERCMD.
              </p>

              <span className="setting-status">
                {TOOLS.length}{" "}
                ACTIVE
              </span>
            </div>

            <div className="panel setting-card">
              <div className="eyebrow">
                ARCHITECTURE
              </div>

              <h3>
                Application Stack
              </h3>

              <p>
                React frontend → Express API → security tools → MySQL.
              </p>

              <span className="setting-status">
                OPERATIONAL
              </span>
            </div>
          </div>
        </section>
      );
    };

  // =========================================================
  // MAIN APPLICATION
  // =========================================================

  return (
    <div className="app">
      {/* SIDEBAR */}

      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">
            C
          </div>

          <div>
            <h1>
              CYBERCMD
            </h1>

            <span>
              SECURITY COMMAND CENTER
            </span>
          </div>
        </div>

        <div className="sidebar-section">
          <p>
            TOOLS
          </p>

          {TOOLS.map(
            (tool) => (
              <button
                key={
                  tool.name
                }
                className={`tool-button ${
                  activeWorkspace ===
                    "scanner" &&
                  selectedTool ===
                    tool.name
                    ? "active"
                    : ""
                }`}
                onClick={() =>
                  selectTool(
                    tool.name
                  )
                }
              >
                <span className="tool-dot"></span>

                {tool.name}
              </button>
            )
          )}
        </div>

        <div className="sidebar-section workspace">
          <p>
            WORKSPACE
          </p>

          <button
            className={`tool-button ${
              activeWorkspace ===
              "history"
                ? "active"
                : ""
            }`}
            onClick={() => {
              setActiveWorkspace(
                "history"
              );

              setSelectedHistoryScan(
                null
              );

              setHistoryDetailError(
                ""
              );
            }}
          >
            <span className="tool-dot"></span>

            Scan History
          </button>

          <button
            className={`tool-button ${
              activeWorkspace ===
              "reports"
                ? "active"
                : ""
            }`}
            onClick={() =>
              setActiveWorkspace(
                "reports"
              )
            }
          >
            <span className="tool-dot"></span>

            Reports
          </button>

          <button
            className={`tool-button ${
              activeWorkspace ===
              "settings"
                ? "active"
                : ""
            }`}
            onClick={() =>
              setActiveWorkspace(
                "settings"
              )
            }
          >
            <span className="tool-dot"></span>

            Settings
          </button>
        </div>

        <div className="sidebar-footer">
          <span
            className={`online-dot ${
              backendOnline
                ? ""
                : "offline"
            }`}
          ></span>

          {backendOnline
            ? "Backend connected"
            : "Backend offline"}
        </div>
      </aside>

      {/* MAIN CONTENT */}

      <main className="main">
        <header className="topbar">
          <div>
            <h2>
              Security Command Center
            </h2>

            <p>
              Security testing workspace
            </p>
          </div>

          <div className="api-status">
            <span></span>

            {backendOnline
              ? "SYSTEM ONLINE"
              : "SYSTEM OFFLINE"}
          </div>
        </header>

        {activeWorkspace ===
          "scanner" &&
          renderScanner()}

        {activeWorkspace ===
          "history" &&
          renderHistory()}

        {activeWorkspace ===
          "reports" &&
          renderReports()}

        {activeWorkspace ===
          "settings" &&
          renderSettings()}
      </main>
    </div>
  );
}

export default App;