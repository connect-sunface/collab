// utils/emailService.js
const nodemailer = require('nodemailer');
require('dotenv').config();

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Verify transporter before sending (optional for startup diagnostics)
transporter.verify((error, success) => {
  if (error) {
    console.error('❌ Email transporter error:', error.message);
  } else {
    console.log('✅ Email transporter is ready');
  }
});

async function sendOTPEmail(to, otp) {
  const mailOptions = {
    from: `"OTP Service" <${process.env.EMAIL_USER}>`,
    to,
    subject: 'Your OTP Code',
    html: `
      <div style="font-family: Arial, sans-serif; padding: 10px;">
        <h2>🔐 OTP Verification</h2>
        <p>Your OTP code is: <strong style="font-size: 1.5em;">${otp}</strong></p>
        <p>This OTP is valid for <strong>5 minutes</strong>.</p>
        <p>If you did not request this, please ignore this email.</p>
      </div>
    `,
  };

  try {
    const result = await transporter.sendMail(mailOptions);
    console.log(`📧 OTP sent to ${to}: ${result.messageId}`);
  } catch (err) {
    console.error('❌ Failed to send OTP email:', err.message);
    throw new Error('Failed to send OTP email');
  }
}

module.exports = sendOTPEmail;
