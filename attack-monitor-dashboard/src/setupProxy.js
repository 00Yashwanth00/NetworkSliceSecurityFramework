// Dev-server proxy (runs in Node, picked up automatically by react-scripts).
// The browser only ever talks to this same origin; Redis and mmt-core are never
// called directly from browser JS (spec section 4).
const { createProxyMiddleware } = require('http-proxy-middleware');

module.exports = function setupProxy(app) {
  const dashboard = process.env.DASHBOARD_BACKEND || 'http://localhost:8787';
  const core = process.env.MMT_CORE_URL || 'http://localhost:5000';

  // Our pipeline state (verdicts, mitigations + bundled core snapshot)
  app.use(createProxyMiddleware('/api/dashboard-data', { target: dashboard, changeOrigin: true }));

  // mmt-core ground truth (audit log, IDS signatures). mmt-core sends no CORS headers,
  // so we proxy it here.
  app.use(createProxyMiddleware('/api/security', { target: core, changeOrigin: true }));
};
