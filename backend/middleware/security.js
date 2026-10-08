const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,

  message: {
    success: false,
    error: "Too many requests. Please try again later.",
  },
});

function configureSecurity(app) {
  app.use(
    helmet({
      crossOriginResourcePolicy: false,
    })
  );

  app.use(limiter);
}

module.exports = {
  configureSecurity,
};