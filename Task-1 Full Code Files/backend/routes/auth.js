const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');

const router = express.Router();
const JWT_SECRET = 'your_jwt_secret_key_here'; // Use environment variable in production

const sendOTPEmail = require('../utils/emailService');

// In-memory OTP stores (for demo purpose)
const otpStore = {};       // For signup
const resetOtpStore = {};  // For forgot-password

// Helper: Validate Email
function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// ===================== SIGNUP FLOW =====================

// 🔹 Request OTP for Signup
router.post('/signup/request-otp', async (req, res) => {
  const { email } = req.body;
  const otp = Math.floor(100000 + Math.random() * 900000).toString();

  otpStore[email] = { otp, expires: Date.now() + 5 * 60 * 1000 };

  try {
    await sendOTPEmail(email, otp);
    res.json({ message: 'OTP sent to your email' });
  } catch (error) {
    console.error('Email sending failed:', error);
    res.status(500).json({ message: 'Failed to send OTP email' });
  }
});

// 🔹 Resend OTP for Signup
router.post('/signup/resend-otp', async (req, res) => {
  const { email } = req.body;
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  otpStore[email] = { otp, expires: Date.now() + 5 * 60 * 1000 };

  try {
    await sendOTPEmail(email, otp);
    res.json({ message: 'OTP resent to your email' });
  } catch (error) {
    console.error('Email sending failed:', error);
    res.status(500).json({ message: 'Failed to resend OTP email' });
  }
});

// 🔹 Verify OTP
router.post('/signup/verify-otp', (req, res) => {
  const { email, otp } = req.body;
  const record = otpStore[email];

  if (!record) return res.status(400).json({ message: 'No OTP sent to this email' });
  if (Date.now() > record.expires) return res.status(400).json({ message: 'OTP expired' });
  if (record.otp !== otp) return res.status(400).json({ message: 'Invalid OTP' });

  delete otpStore[email]; // Clean up
  res.json({ message: 'Email verified successfully' });
});

// 🔹 Signup
router.post('/signup', async (req, res) => {
  const { username, phone, email, password } = req.body;

  try {
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists with this email or username' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, phone, email, password: hashedPassword });

    await newUser.save();
    res.status(201).json({ message: 'User created successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error during signup' });
  }
});

// ===================== LOGIN =====================

router.post('/login', async (req, res) => {
  const { identifier, password } = req.body;

  try {
    let user;
    if (isValidEmail(identifier)) {
      user = await User.findOne({ email: identifier });
    } else {
      user = await User.findOne({ username: identifier });
    }

    if (!user) return res.status(400).json({ message: 'Invalid credentials' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '1h' });

    res.json({
      token,
      user: {
        username: user.username,
        email: user.email,
       
      },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error during login' });
  }
});

// ===================== FORGOT PASSWORD FLOW =====================

// 🔹 Request OTP for password reset
router.post('/forgot-password/request-otp', async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'Email not registered' });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    resetOtpStore[email] = { otp, expires: Date.now() + 5 * 60 * 1000 };

    await sendOTPEmail(email, otp);
    res.json({ message: 'OTP sent to your email' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error sending OTP' });
  }
});

// 🔹 Resend OTP for password reset
router.post('/forgot-password/resend-otp', async (req, res) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'Email not registered' });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    resetOtpStore[email] = { otp, expires: Date.now() + 5 * 60 * 1000 };

    await sendOTPEmail(email, otp);
    res.json({ message: 'OTP resent to your email' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to resend OTP' });
  }
});

// 🔹 Verify OTP for password reset
router.post('/forgot-password/verify-otp', (req, res) => {
  const { email, otp } = req.body;
  const record = resetOtpStore[email];

  if (!record) return res.status(400).json({ message: 'No OTP sent to this email' });
  if (Date.now() > record.expires) return res.status(400).json({ message: 'OTP expired' });
  if (record.otp !== otp) return res.status(400).json({ message: 'Invalid OTP' });

  res.json({ message: 'OTP verified successfully' });
});

// 🔹 Reset password
router.post('/forgot-password/reset', async (req, res) => {
  const { email, newPassword } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'Email not registered' });

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();

    delete resetOtpStore[email];
    res.json({ message: 'Password reset successful' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error resetting password' });
  }
});

// ===========  FIREBASE STORE FOR CONTINUE WITH GOOGLE ACCOUNTS ===============

router.post('/firebase', async (req, res) => {
  try {
    console.log("Received /firebase request:", req.body);

    let { username, email, phone, method } = req.body;
    if (!username) username = "Google User";
    if (!method) method = "google";
    if (!email && !phone) {
      return res.status(400).json({ message: 'Email or phone number required' });
    }

    const existingUser = await User.findOne({ $or: [{ email }, { phone }] });

    if (existingUser) {
      if (existingUser.method && existingUser.method !== method) {
        return res.status(400).json({ message: 'User exists with a different sign-in method' });
      }
      const token = jwt.sign({ id: existingUser._id }, JWT_SECRET, { expiresIn: '1h' });
      return res.status(200).json({
        message: 'User already exists',
        token,
        user: {
          username: existingUser.username,
          email: existingUser.email,
          phone: existingUser.phone,
          method: existingUser.method
        }
      });
    }

    // Create new user (no password for Google)
    const newUser = new User({ username, email, phone, method });
    await newUser.save().catch(err => {
      console.error("Mongoose save error:", err);
      throw err;
    });

    const token = jwt.sign({ id: newUser._id }, JWT_SECRET, { expiresIn: '1h' });

    res.status(201).json({
      message: 'Firebase user saved successfully',
      token,
      user: {
        username: newUser.username,
        email: newUser.email,
        phone: newUser.phone,
        method: newUser.method
      }
    });
  } catch (err) {
    console.error("Error saving Firebase user:", err);
    res.status(500).json({ message: 'Error saving Firebase user', error: err.message });
  }
});


// ===========  FIREBASE STORE FOR CONTINUE WITH MOBILE OTP ===============


router.post('/firebase/phone-login', async (req, res) => {
  const { phone } = req.body;

  try {
    let user = await User.findOne({ phone });

    if (!user) {
      const generatedUsername = 'user_' + Math.floor(Math.random() * 1000000);
      user = new User({
        username: generatedUsername,
        phone,
        password: '',      // Optional
        method: 'otp',     // If using a method field
      });
      await user.save();
    }

    // Generate JWT token
    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '1h' });

    res.json({
      message: 'User stored successfully',
      token,
      user: {
        username: user.username,
        phone: user.phone,
        method: user.method
      }
    });
  } catch (err) {
    console.error('Error saving Firebase phone user:', err.message);
    res.status(500).json({ message: 'Server error' });
  }
});


//// ###### VERIFY MY TOKEN OF LOGIN METHODS ##############

function verifyToken(req, res, next) {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ message: 'No token provided' });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: 'Invalid token' });
        }
        req.user = decoded;
        next();
    });
}

//// ###### CHANGE MY NAME CODE FOR ALL LOGIN METHODS ##############

router.put('/update-profile', async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader) {
            return res.status(401).json({ message: 'No token provided' });
        }

        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        const userId = decoded.id;

        const updateData = req.body;

        if (!updateData.username || updateData.username.trim().length < 3) {
            return res.status(400).json({ message: 'Username must be at least 3 characters' });
        }

        const existingUser = await User.findOne({ 
            username: updateData.username, 
            _id: { $ne: userId } 
        });

        if (existingUser) {
            return res.status(400).json({ message: 'Username is already taken' });
        }

        const updatedUser = await User.findByIdAndUpdate(
            userId,
            { $set: updateData },
            { new: true, runValidators: true }
        );

        if (!updatedUser) {
            return res.status(404).json({ message: 'User not found' });
        }

        const { password, ...userData } = updatedUser.toObject();
        return res.status(200).json({ message: 'Profile updated', user: userData });

    } catch (err) {
        console.error('Profile update error:', err);

        if (err.name === 'JsonWebTokenError') {
            return res.status(401).json({ message: 'Invalid token' });
        }

        if (err.name === 'TokenExpiredError') {
            return res.status(401).json({ message: 'Token expired' });
        }

        return res.status(500).json({ message: 'Server error during profile update' });
    }
});

//// ###### UPDATE MY MAIL ID FOR ALL LOGIN METHODS ##############

const updateEmailOtpStore = {};  

router.post('/update-email/request-otp', verifyToken, async (req, res) => {
    const { newEmail } = req.body;
    const userId = req.user.id;

    try {
        // Validate email format
        if (!isValidEmail(newEmail)) {
            return res.status(400).json({ message: 'Invalid email format' });
        }

        // Check if email is already used
        const existingUser = await User.findOne({ email: newEmail });
        if (existingUser) {
            return res.status(400).json({ message: 'Email already in use' });
        }

        // Generate OTP
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        updateEmailOtpStore[userId] = { 
            otp, 
            newEmail,
            expires: Date.now() + 5 * 60 * 1000 // 5 minutes
        };

        // Send OTP via email
        await sendOTPEmail(newEmail, otp);
        res.json({ message: 'OTP sent to your new email' });
    } catch (err) {
        console.error('Email update OTP error:', err);
        res.status(500).json({ message: 'Error sending OTP' });
    }
});

// 🔹 Verify OTP and update email
router.post('/update-email/verify-otp', verifyToken, async (req, res) => {
    const { otp, newEmail } = req.body;
    const userId = req.user.id;

    try {
        const record = updateEmailOtpStore[userId];
        if (!record) {
            return res.status(400).json({ message: 'No OTP request found' });
        }

        if (Date.now() > record.expires) {
            delete updateEmailOtpStore[userId];
            return res.status(400).json({ message: 'OTP expired' });
        }

        if (record.otp !== otp) {
            return res.status(400).json({ message: 'Invalid OTP' });
        }

        //  Check if this new email is already used by some other user
        const alreadyUsed = await User.findOne({ email: newEmail, _id: { $ne: userId } });
        if (alreadyUsed) {
            return res.status(400).json({ message: 'Email already in use' });
        }

        const user = await User.findByIdAndUpdate(
            userId,
            { email: newEmail },
            { new: true }
        );

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        delete updateEmailOtpStore[userId];

        res.json({
            message: 'Email updated successfully',
            user: {
                email: user.email,
                username: user.username,
                phone: user.phone
            }
        });

    } catch (err) {
        console.error('Email update error:', err);
        res.status(500).json({ message: 'Error updating email' });
    }
});

// ####33# CHANGE/UPDATE PASSWORD FOR ALL LOGIN METHODS ########

router.put('/update-password', verifyToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const { currentPassword, newPassword } = req.body;

        // Validate new password
        if (!newPassword || newPassword.length < 8) {
            return res.status(400).json({ message: 'Password must be at least 8 characters' });
        }

        // Find user
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // For password users, verify current password
        if (user.method === 'password') {
            if (!currentPassword) {
                return res.status(400).json({ message: 'Current password is required' });
            }
            
            const isMatch = await bcrypt.compare(currentPassword, user.password);
            if (!isMatch) {
                return res.status(400).json({ message: 'Current password is incorrect' });
            }
        }

        if (!user.method) {
            user.method = 'password'; // fallback if user created without method
        }

        // Hash and save new password
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedPassword;
        
        await user.save();

        res.json({ 
            message: 'Password updated successfully',
            user: {
                username: user.username,
                email: user.email,
                phone: user.phone
            }
        });
    } catch (err) {
        console.error('Password update error:', err);
        
        if (err.name === 'JsonWebTokenError') {
            return res.status(401).json({ message: 'Invalid token' });
        }

        res.status(500).json({ message: 'Server error during password update' });
    }
});

// ############333 UPDATE PHONE NUMBER FOR ALL LOGIN METHODS ################

router.put('/update-phone', verifyToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const { phone } = req.body;

        // Validate phone format for India
        if (!phone || !/^\+91\d{10}$/.test(phone)) {
            return res.status(400).json({ 
                message: 'Phone number must be in +91 format followed by 10 digits (e.g. +911234567890)' 
            });
        }

        // Check if phone is already used by another account
        const existingUser = await User.findOne({ 
            $or: [
                { phone: phone },
                { email: phone }, // Also check if used as email
                { username: phone } // Also check if used as username
            ],
            _id: { $ne: userId } 
        });

        if (existingUser) {
            return res.status(400).json({ 
                message: 'Phone number is already associated with another account' 
            });
        }

        // Update phone number
        const updatedUser = await User.findByIdAndUpdate(
            userId,
            { phone: phone },
            { new: true, runValidators: true }
        );

        if (!updatedUser) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Return updated user info (without password)
        const { password, ...userData } = updatedUser.toObject();
        return res.status(200).json({ 
            message: 'Phone number updated successfully',
            user: userData
        });

    } catch (err) {
        console.error('Phone update error:', err);
        return res.status(500).json({ message: 'Server error during phone update' });
    }
});

// ########### FIND USER BY PHONE ###################
// ########## INTEGRATING PHONE WITH EMAIL ID'S ##########

router.post('/find-user-by-phone', async (req, res) => {
    try {
        const { phone } = req.body;
        
        // Find user by phone across all login methods
        const user = await User.findOne({ phone });
        
        if (user) {
            // Generate token
            const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '1h' });
            
            return res.json({
                user: {
                    _id: user._id,
                    username: user.username,
                    email: user.email,
                    phone: user.phone,
                    method: user.method
                },
                token
            });
        }
        
        // Return empty if not found
        res.json({ user: null });
    } catch (err) {
        console.error('Find user error:', err);
        res.status(500).json({ message: 'Server error' });
    }
});

module.exports = router;