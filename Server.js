require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const { Sequelize, DataTypes } = require('sequelize');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Config (override using .env)
const JWT_SECRET = process.env.JWT_SECRET || 'supersecret_jwt_key';
const PORT = process.env.PORT || 3000;
const SALT_ROUNDS = 10;

// SQLite via Sequelize (file: database.sqlite)
const sequelize = new Sequelize({
  dialect: 'sqlite',
  storage: process.env.DB_FILE || 'database.sqlite',
  logging: false
});

// Models
const Employee = sequelize.define('Employee', {
  email: { type: DataTypes.STRING, allowNull: false, unique: true },
  name: { type: DataTypes.STRING },
  passwordHash: { type: DataTypes.STRING, allowNull: false }
}, { timestamps: true });

const Enquiry = sequelize.define('Enquiry', {
  name: { type: DataTypes.STRING, allowNull: false },
  email: { type: DataTypes.STRING },
  courseInterest: { type: DataTypes.STRING },
  phone: { type: DataTypes.STRING },
  notes: { type: DataTypes.TEXT },
  // claimedByEmployeeId will store the Employee.id when claimed
  claimedByEmployeeId: { type: DataTypes.INTEGER, allowNull: true },
  claimedAt: { type: DataTypes.DATE, allowNull: true }
}, { timestamps: true });

// Relationships (optional, makes joins easier)
Employee.hasMany(Enquiry, { foreignKey: 'claimedByEmployeeId' });
Enquiry.belongsTo(Employee, { foreignKey: 'claimedByEmployeeId', as: 'claimedBy' });

// Middleware: authenticate JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Missing Authorization header' });

  const token = authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Malformed Authorization header' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(401).json({ error: 'Invalid or expired token' });
    req.user = user; // contains { id, email }
    next();
  });
}

// Routes

// Health
app.get('/', (req, res) => res.json({ status: 'ok', service: 'CRM backend' }));

/**
 * Register
 * POST /auth/register
 * body: { name, email, password }
 */
app.post('/auth/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'email and password required' });

    const existing = await Employee.findOne({ where: { email }});
    if (existing) return res.status(409).json({ error: 'Email already registered' });

    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
    const employee = await Employee.create({ email, name: name || null, passwordHash });
    return res.status(201).json({ id: employee.id, email: employee.email, name: employee.name });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Registration failed' });
  }
});

/**
 * Login
 * POST /auth/login
 * body: { email, password }
 * returns: { token }
 */
app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'email and password required' });

    const employee = await Employee.findOne({ where: { email }});
    if (!employee) return res.status(401).json({ error: 'Invalid credentials' });

    const ok = await bcrypt.compare(password, employee.passwordHash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ id: employee.id, email: employee.email }, JWT_SECRET, { expiresIn: '8h' });
    return res.json({ token, id: employee.id, email: employee.email, name: employee.name });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Login failed' });
  }
});

/**
 * Public enquiry form (no auth)
 * POST /enquiries/public
 * body: { name, email, courseInterest, phone, notes }
 */
app.post('/enquiries/public', async (req, res) => {
  try {
    const { name, email, courseInterest, phone, notes } = req.body;
    if (!name) return res.status(400).json({ error: 'name is required' });

    const e = await Enquiry.create({ name, email, courseInterest, phone, notes });
    return res.status(201).json({ id: e.id, message: 'Enquiry submitted' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Failed to submit enquiry' });
  }
});

/**
 * Get unclaimed leads (Public Enquiries)
 * GET /enquiries/public
 * auth required
 * Query params: ?limit=20&offset=0
 */
app.get('/enquiries/public', authenticateToken, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 50, 200);
    const offset = parseInt(req.query.offset) || 0;

    const { count, rows } = await Enquiry.findAndCountAll({
      where: { claimedByEmployeeId: null },
      order: [['createdAt', 'DESC']],
      limit,
      offset
    });

    return res.json({ total: count, enquiries: rows });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Failed to fetch public enquiries' });
  }
});

/**
 * Claim an enquiry:
 * POST /enquiries/:id/claim
 * auth required
 */
app.post('/enquiries/:id/claim', authenticateToken, async (req, res) => {
  try {
    const enquiryId = parseInt(req.params.id);
    if (isNaN(enquiryId)) return res.status(400).json({ error: 'Invalid enquiry id' });

    // Transaction to avoid race conditions
    const result = await sequelize.transaction(async (t) => {
      const enquiry = await Enquiry.findOne({ where: { id: enquiryId }, lock: t.LOCK.UPDATE, transaction: t });
      if (!enquiry) throw { status: 404, message: 'Enquiry not found' };
      if (enquiry.claimedByEmployeeId) throw { status: 409, message: 'Enquiry already claimed' };

      enquiry.claimedByEmployeeId = req.user.id;
      enquiry.claimedAt = new Date();
      await enquiry.save({ transaction: t });
      return enquiry;
    });

    return res.json({ message: 'Enquiry claimed', enquiry: result });
  } catch (err) {
    console.error(err);
    if (err && err.status) return res.status(err.status).json({ error: err.message });
    return res.status(500).json({ error: 'Failed to claim enquiry' });
  }
});

/**
 * Fetch leads claimed by logged-in user (Private Enquiries)
 * GET /enquiries/mine
 */
app.get('/enquiries/mine', authenticateToken, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 50, 200);
    const offset = parseInt(req.query.offset) || 0;

    const { count, rows } = await Enquiry.findAndCountAll({
      where: { claimedByEmployeeId: req.user.id },
      order: [['claimedAt', 'DESC']],
      limit,
      offset
    });

    return res.json({ total: count, enquiries: rows });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Failed to fetch your enquiries' });
  }
});

// (Optional) Endpoint to view an enquiry detail if claimed by the user or public
app.get('/enquiries/:id', authenticateToken, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const enquiry = await Enquiry.findByPk(id, { include: [{ model: Employee, as: 'claimedBy', attributes: ['id','email','name'] }] });
    if (!enquiry) return res.status(404).json({ error: 'Enquiry not found' });

    // if claimed and claimed by another user, block details
    if (enquiry.claimedByEmployeeId && enquiry.claimedByEmployeeId !== req.user.id) {
      return res.status(403).json({ error: 'You are not allowed to view this enquiry' });
    }

    return res.json(enquiry);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Failed to fetch enquiry' });
  }
});

// Sync DB and start server
(async () => {
  try {
    await sequelize.authenticate();
    await sequelize.sync({ alter: true }); // safe for development; adjust for production
    console.log('DB connected & models synced');

    app.listen(PORT, () => {
      console.log(`CRM backend listening on port ${PORT}`);
      console.log(`JWT_SECRET=${JWT_SECRET ? '*** set ***' : '*** default used ***'}`);
    });
  } catch (err) {
    console.error('Failed to start server', err);
  }
})();
