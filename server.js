// server.js (Corrected Version)

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const path = require('path');
require('dotenv').config();

const app = express();

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// Middleware
app.use(helmet());
app.use(cors({ origin: process.env.FRONTEND_URL || '*', credentials: true }));
app.use(express.json());

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log('✅ MongoDB connected'))
  .catch(err => console.log('MongoDB error:', err));

// =================== SCHEMAS =================== //
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  role: { type: String, enum: ['admin', 'user'], default: 'user' },
  phone: String,
  bloodGroup: String,
  city: String
});
const User = mongoose.model('User', userSchema);

const requestSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  bloodGroup: { type: String, required: true },
  units: { type: Number, required: true },
  city: { type: String, required: true },
  status: { type: String, enum: ['Pending', 'Approved', 'Rejected'], default: 'Pending' }
}, { timestamps: true });
const BloodRequest = mongoose.model('BloodRequest', requestSchema);

const donationSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  date: { type: Date, required: true },
  center: { type: String, required: true },
  city: { type: String, required: true },
  status: { type: String, default: 'Scheduled' },
  createdAt: { type: Date, default: Date.now }
});
const Donation = mongoose.model('Donation', donationSchema);

const bloodStockSchema = new mongoose.Schema({
  bloodGroup: String,
  units: Number,
  location: String,
  contact: String
});
const BloodStock = mongoose.model('BloodStock', bloodStockSchema);

// =================== MIDDLEWARE =================== //
const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  try {
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ error: 'Invalid token' });
  }
};

const isAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// =================== DEFAULT ADMIN =================== //
const createDefaultAdmin = async () => {
  const existingAdmin = await User.findOne({ email: 'admin@lifeflow.com' });
  if (!existingAdmin) {
    const hashed = await bcrypt.hash('admin123', 10);
    await User.create({
      name: 'Default Admin',
      email: 'admin@lifeflow.com',
      password: hashed,
      role: 'admin'
    });
    console.log('✅ Default admin created');
  }
};
createDefaultAdmin();

// =================== ROUTES =================== //

// --- Auth ---
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (await User.findOne({ email }))
      return res.status(400).json({ error: 'Email already exists' });

    const hashed = await bcrypt.hash(password, 10);
    const user = await User.create({ name, email, password: hashed });
    res.status(201).json({ message: 'Registered successfully', user });
  } catch {
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { email, password, role } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (role && user.role !== role)
      return res.status(403).json({ error: `Not authorized as ${role}` });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, {
      expiresIn: process.env.JWT_EXPIRES_IN || '1h'
    });

    res.json({
      success: true,
      message: 'Login successful',
      token,
      role: user.role,
      user: { id: user._id, name: user.name, email: user.email }
    });
  } catch {
    res.status(500).json({ error: 'Login failed' });
  }
});

// --- Profile ---
app.get('/api/user/me', authenticate, async (req, res) => {
  const user = await User.findById(req.user.id).select('-password');
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json(user);
});

app.put('/api/user/profile', authenticate, async (req, res) => {
  const { name, phone, bloodGroup, city } = req.body;
  const user = await User.findByIdAndUpdate(
    req.user.id,
    { name, phone, bloodGroup, city },
    { new: true }
  ).select('-password');
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ message: 'Profile updated successfully', user });
});

// --- Blood Request ---
app.post('/api/blood/request', authenticate, async (req, res) => {
  const { bloodGroup, units, city } = req.body;
  if (!bloodGroup || !units || !city)
    return res.status(400).json({ error: 'All fields are required' });

  const request = await BloodRequest.create({ userId: req.user.id, bloodGroup, units, city });
  res.status(201).json({ message: 'Request submitted', request });
});

app.get('/api/user/requests', authenticate, async (req, res) => {
  const requests = await BloodRequest.find({ userId: req.user.id }).sort({ createdAt: -1 });
  res.json(requests);
});

// --- Donation ---
app.post('/api/donation/schedule', authenticate, async (req, res) => {
  const { date, center, city } = req.body;
  if (!date || !center || !city)
    return res.status(400).json({ message: 'All fields required' });

  const donation = new Donation({ userId: req.user.id, date: new Date(date), center, city });
  await donation.save();
  res.status(201).json({ message: 'Donation scheduled' });
});

app.get('/api/donation/history', authenticate, async (req, res) => {
  try {
    const history = await Donation.find({ userId: req.user.id }).sort({ date: -1 });
    res.json(history);
  } catch (error) {
    res.status(500).json({ message: 'Server error while fetching history' });
  }
});

// --- Blood Availability ---
app.post('/api/search-blood', async (req, res) => {
  const { bloodGroup, location } = req.body;
  const results = await BloodStock.find({
    bloodGroup,
    location: { $regex: new RegExp(location, 'i') }
  });
  res.json(results);
});

app.get('/api/add-sample-stock', async (req, res) => {
  try {
    await BloodStock.deleteMany();
    await BloodStock.insertMany([
      { bloodGroup: 'A+', units: 5, location: 'Hyderabad', contact: '9876543210' },
      { bloodGroup: 'O-', units: 2, location: 'Chennai', contact: '9123456789' },
      { bloodGroup: 'B+', units: 4, location: 'Hyderabad', contact: '9000000001' },
      { bloodGroup: 'AB+', units: 6, location: 'Bangalore', contact: '9988776655' }
    ]);
    res.send('✅ Sample blood stock added');
  } catch {
    res.status(500).send('❌ Failed to add stock');
  }
});

// --- Admin ---
app.get('/api/admin/users', authenticate, isAdmin, async (req, res) => {
  const users = await User.find({ email: { $ne: 'admin@lifeflow.com' } }).select('-password');
  res.json({ users });
});

app.delete('/api/admin/users/:id', authenticate, isAdmin, async (req, res) => {
  const deleted = await User.findByIdAndDelete(req.params.id);
  if (!deleted) return res.status(404).json({ error: 'User not found' });
  res.json({ message: 'User deleted' });
});

app.put('/api/admin/users/:id', authenticate, isAdmin, async (req, res) => {
  const { name, email, role } = req.body;
  const updated = await User.findByIdAndUpdate(
    req.params.id,
    { name, email, role },
    { new: true, runValidators: true }
  );
  if (!updated) return res.status(404).json({ error: 'User not found' });
  res.json({ message: 'User updated', user: updated });
});
// Middleware to authenticate JWT token

function authenticateUser(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid token' });
  }
}

// Admin - Get all blood requests
app.get('/api/admin/blood-requests', authenticate, isAdmin, async (req, res) => {
  try {
    const requests = await BloodRequest.find().populate('userId', 'name email city');
    res.json(requests);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching blood requests' });
  }
});
// Admin - View all scheduled donations
app.get('/api/admin/donations', authenticate, isAdmin, async (req, res) => {
  try {
    const donations = await Donation.find()
      .populate('userId', 'name email city')
      .sort({ date: -1 });

    res.json(donations);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching donations' });
  }
});
const inventorySchema = new mongoose.Schema({
  bloodGroup: String,
  units: Number,
  location: String,
  contact: String
});

const Inventory = mongoose.model('Inventory', inventorySchema);
// Add this at the top
// adjust path if needed

// Admin: Get Inventory
app.get('/api/admin/inventory', authenticate, isAdmin, async (req, res) => {
  try {
    const inventory = await Inventory.find();
    res.json(inventory);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Admin: Add or Update Inventory
app.post('/api/admin/inventory', authenticate, isAdmin, async (req, res) => {
  const { bloodGroup, units, location, contact } = req.body;
  try {
    const existing = await Inventory.findOne({ bloodGroup, location });
    if (existing) {
      existing.units = units;
      existing.contact = contact;
      await existing.save();
      res.json({ message: 'Inventory updated' });
    } else {
      const newEntry = new Inventory({ bloodGroup, units, location, contact });
      await newEntry.save();
      res.json({ message: 'Inventory added' });
    }
  } catch (err) {
    res.status(500).json({ error: 'Failed to save inventory' });
  }
});






// --- Root ---
app.get('/', (req, res) => {
  res.send('🚀 LifeFlow server running!');
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🌐 Server running at http://localhost:${PORT}`));
