// test.js
const sendOTPEmail = require('./utils/emailService');

sendOTPEmail('receiver@example.com', '123456')
  .then(() => console.log('Test OTP sent'))
  .catch(err => console.error('Error:', err.message));
