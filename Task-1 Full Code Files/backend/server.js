const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');
const authRoutes = require('./routes/auth');

const app = express();
const PORT = 5000;

// MongoDB Connection
mongoose.connect('mongodb+srv://vgugan16:gugan2004@cluster0.qyh1fuo.mongodb.net/dL?retryWrites=true&w=majority&appName=Cluster0', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});
mongoose.connection.on('connected', () => {
  console.log('✅ Connected to MongoDB');
});
mongoose.connection.on('error', (err) => {
  console.error('❌ MongoDB connection error:', err);
});

// CORS
const corsOptions = {
  origin: 'http://127.0.0.1:5500',
  credentials: true,
};
app.use(cors(corsOptions));

// Middleware
app.use(bodyParser.json());
app.use(express.json());

// Routes
app.use('/api/auth', authRoutes);

// Catch-all 404 JSON handler
app.use((req, res) => {
  res.status(404).json({ message: 'Route not found' });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Server is running at http://localhost:${PORT}`);
});
