const { pool } = require("../config/database");

async function saveScan(scan) {
  const query = `
    INSERT INTO scans
    (
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
  `;

  const values = [
    scan.tool,
    scan.target,
    scan.status,
    scan.duration ?? null,
    scan.httpStatus ?? null,
    scan.openPorts ?? null,
    scan.services ?? null,
    scan.result ?? null,
    scan.error ?? null,
  ];

  const [result] = await pool.execute(query, values);

  return {
    id: result.insertId,
    ...scan,
  };
}

async function getScans() {
  const [rows] = await pool.query(`
    SELECT
      id,
      tool,
      target,
      status,
      duration,
      http_status,
      open_ports,
      services,
      created_at
    FROM scans
    ORDER BY created_at DESC
    LIMIT 100
  `);

  return rows;
}

async function getScanById(id) {
  const [rows] = await pool.execute(
    `
      SELECT *
      FROM scans
      WHERE id = ?
      LIMIT 1
    `,
    [id]
  );

  return rows[0] || null;
}

async function clearScans() {
  await pool.query("DELETE FROM scans");
}

module.exports = {
  saveScan,
  getScans,
  getScanById,
  clearScans,
};