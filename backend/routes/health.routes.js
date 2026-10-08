const express = require("express");
const { checkDatabaseConnection } = require("../config/database");

const router = express.Router();

router.get("/", async (req, res) => {
  let database = "offline";

  try {
    await checkDatabaseConnection();
    database = "online";
  } catch (error) {
    database = "offline";
  }

  const healthy = database === "online";

  res.status(healthy ? 200 : 503).json({
    success: healthy,
    application: "CYBERCMD",
    backend: "online",
    database,
    timestamp: new Date().toISOString(),
  });
});

module.exports = router;