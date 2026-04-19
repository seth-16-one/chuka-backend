require('dotenv').config();

const cors = require('cors');
const express = require('express');

const authRoutes = require('./routes/auth');

const app = express();
const port = Number(process.env.PORT || 3000);

app.use(
  cors({
    origin: process.env.CORS_ORIGIN ? process.env.CORS_ORIGIN.split(',').map((value) => value.trim()) : true,
  })
);
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));

app.get('/', (_req, res) => {
  res.json({
    service: 'chuka-backend',
    status: 'ok',
    timestamp: new Date().toISOString(),
  });
});

app.get('/health', (_req, res) => {
  res.status(200).json({ ok: true });
});

app.use('/api', authRoutes);

app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({
    error: err instanceof Error ? err.message : 'Internal server error.',
  });
});

app.listen(port, '0.0.0.0', () => {
  console.log(`Chuka backend listening on port ${port}`);
});
