'use strict';

/**
 * Creates the dashboard middleware
 * @param {Object} options 
 * @param {Object} logger Instance of Logger
 * @returns {Function} Express/Connect middleware
 */
function createDashboardHandler(options = {}, logger) {
  const path = options.path || '/__fortifyjs/dashboard';
  const apiEventsPath = `${path}/api/events`;
  const apiStatsPath = `${path}/api/stats`;
  
  const authMiddleware = options.auth || ((req, res, next) => {
    logger.warn('Dashboard accessed without authentication configured!');
    next();
  });

  const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>FortifyJS Dashboard</title>
  <style>
    :root {
      --bg: #0f172a;
      --card-bg: rgba(30, 41, 59, 0.7);
      --border: rgba(255, 255, 255, 0.1);
      --text: #f8fafc;
      --text-muted: #94a3b8;
      --accent: #38bdf8;
      --danger: #f43f5e;
      --warning: #fbbf24;
      --success: #10b981;
    }
    body {
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }
    .glass {
      background: var(--card-bg);
      backdrop-filter: blur(10px);
      -webkit-backdrop-filter: blur(10px);
      border: 1px solid var(--border);
      border-radius: 12px;
    }
    header {
      padding: 1rem 2rem;
      border-bottom: 1px solid var(--border);
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    header h1 {
      margin: 0;
      font-size: 1.5rem;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }
    .badge {
      padding: 0.25rem 0.5rem;
      border-radius: 999px;
      font-size: 0.75rem;
      font-weight: bold;
      text-transform: uppercase;
    }
    .badge-danger { background: rgba(244, 63, 94, 0.2); color: var(--danger); }
    .badge-warning { background: rgba(251, 191, 36, 0.2); color: var(--warning); }
    .badge-success { background: rgba(16, 185, 129, 0.2); color: var(--success); }
    main {
      padding: 2rem;
      flex: 1;
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 1.5rem;
      max-width: 1400px;
      margin: 0 auto;
      width: 100%;
      box-sizing: border-box;
    }
    .panel {
      padding: 1.5rem;
      display: flex;
      flex-direction: column;
    }
    .panel h2 {
      margin-top: 0;
      font-size: 1.25rem;
      border-bottom: 1px solid var(--border);
      padding-bottom: 0.75rem;
    }
    .full-width { grid-column: 1 / -1; }
    table {
      width: 100%;
      border-collapse: collapse;
      text-align: left;
    }
    th, td {
      padding: 0.75rem 1rem;
      border-bottom: 1px solid var(--border);
    }
    th {
      color: var(--text-muted);
      font-weight: 600;
      font-size: 0.875rem;
    }
    tbody tr:hover {
      background: rgba(255, 255, 255, 0.05);
    }
    .empty-state {
      padding: 3rem;
      text-align: center;
      color: var(--text-muted);
    }
    .stat-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 1rem;
      margin-bottom: 1.5rem;
    }
    .stat-card {
      padding: 1.5rem;
      text-align: center;
    }
    .stat-value {
      font-size: 2.5rem;
      font-weight: bold;
      margin: 0.5rem 0;
    }
    .stat-label {
      color: var(--text-muted);
      font-size: 0.875rem;
      text-transform: uppercase;
    }
  </style>
</head>
<body>
  <header class="glass">
    <h1>🛡️ FortifyJS</h1>
    <div>
      <span class="badge badge-success">Live Monitoring</span>
    </div>
  </header>
  
  <main>
    <div class="full-width stat-grid" id="stats">
      <!-- Stats will load here -->
    </div>

    <div class="panel glass full-width">
      <h2>Recent Threats Feed</h2>
      <div style="overflow-x: auto;">
        <table id="events-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Threat</th>
              <th>Action</th>
              <th>IP / Actor</th>
              <th>Route</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody>
            <!-- Events load here -->
          </tbody>
        </table>
      </div>
    </div>
  </main>

  <script>
    async function loadData() {
      try {
        const eventsRes = await fetch('${apiEventsPath}');
        const events = await eventsRes.json();
        
        const statsRes = await fetch('${apiStatsPath}');
        const stats = await statsRes.json();

        renderStats(stats);
        renderEvents(events);
      } catch (err) {
        console.error('Failed to load dashboard data', err);
      }
    }

    function renderStats(stats) {
      document.getElementById('stats').innerHTML = \`
        <div class="stat-card glass">
          <div class="stat-label">Total Blocked</div>
          <div class="stat-value" style="color: var(--danger)">\${stats.blocked}</div>
        </div>
        <div class="stat-card glass">
          <div class="stat-label">Total Allowed</div>
          <div class="stat-value" style="color: var(--success)">\${stats.allowed}</div>
        </div>
        <div class="stat-card glass">
          <div class="stat-label">Top Threat</div>
          <div class="stat-value" style="color: var(--warning); font-size: 1.5rem; line-height: 2.5rem;">
            \${stats.topThreat || 'None'}
          </div>
        </div>
      \`;
    }

    function renderEvents(events) {
      const tbody = document.querySelector('#events-table tbody');
      if (!events || events.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6"><div class="empty-state">No threats detected yet.</div></td></tr>';
        return;
      }

      tbody.innerHTML = events.map(e => {
        const date = new Date(e.timestamp).toLocaleTimeString();
        const badgeClass = e.meta?.action === 'block' ? 'badge-danger' : (e.level === 'warn' ? 'badge-warning' : 'badge-success');
        const action = e.meta?.action || 'observe';
        const label = e.meta?.label || 'unknown';
        const ip = e.meta?.ip || 'unknown';
        const route = e.meta?.route || 'unknown';
        
        return \`
          <tr>
            <td style="color: var(--text-muted)">\${date}</td>
            <td><span class="badge \${badgeClass}">\${label}</span></td>
            <td>\${action.toUpperCase()}</td>
            <td><code>\${ip}</code></td>
            <td><code>\${route}</code></td>
            <td style="font-size: 0.875rem; color: var(--text-muted); max-width: 300px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;" title='\${e.message}'>
              \${e.message}
            </td>
          </tr>
        \`;
      }).join('');
    }

    // Refresh every 5 seconds
    loadData();
    setInterval(loadData, 5000);
  </script>
</body>
</html>`;

  return function dashboardMiddleware(req, res, next) {
    if (req.path === path || req.path === path + '/') {
      return authMiddleware(req, res, (err) => {
        if (err) return next(err);
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.end(htmlTemplate);
      });
    }

    if (req.path === apiEventsPath) {
      return authMiddleware(req, res, (err) => {
        if (err) return next(err);
        const logs = logger.getLogs(100).filter(l => l.level === 'warn' || l.level === 'error');
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify(logs));
      });
    }

    if (req.path === apiStatsPath) {
      return authMiddleware(req, res, (err) => {
        if (err) return next(err);
        const allLogs = logger.getLogs(1000);
        const stats = {
          blocked: 0,
          allowed: 0,
          threatCounts: {}
        };

        allLogs.forEach(l => {
          if (l.meta?.action === 'block') stats.blocked++;
          else stats.allowed++;

          if (l.meta?.label) {
            stats.threatCounts[l.meta.label] = (stats.threatCounts[l.meta.label] || 0) + 1;
          }
        });

        let topThreat = null;
        let maxCount = 0;
        for (const [threat, count] of Object.entries(stats.threatCounts)) {
          if (count > maxCount) {
            maxCount = count;
            topThreat = threat;
          }
        }
        stats.topThreat = topThreat;

        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify(stats));
      });
    }

    next();
  };
}

module.exports = { createDashboardHandler };
