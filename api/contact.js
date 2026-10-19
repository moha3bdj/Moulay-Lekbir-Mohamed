/**
 * Vercel Serverless Function: /api/contact
 * Handles contact message submissions with input sanitization and anti-spam honeypot verification.
 */

export default async function handler(req, res) {
  // Set hardened security headers on the API response
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({
      success: false,
      error: 'Method Not Allowed. Only POST requests are permitted.'
    });
  }

  try {
    const body = req.body || {};
    const { name, email, subject, message, _gotcha } = body;

    // 1. Anti-Spam Honeypot Verification
    // Automated bots fill hidden fields; humans leave it blank.
    if (_gotcha && String(_gotcha).trim().length > 0) {
      // Respond 200 OK so bots assume success, but silently drop the payload
      return res.status(200).json({
        success: true,
        message: 'Message received.'
      });
    }

    // 2. Strict Input Validation & Length Bounds
    if (!name || typeof name !== 'string' || name.trim().length < 2 || name.trim().length > 100) {
      return res.status(400).json({
        success: false,
        error: 'Please provide a valid name (2 to 100 characters).'
      });
    }

    const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;
    const cleanEmail = String(email || '').trim();
    if (!cleanEmail || cleanEmail.length > 150 || !emailRegex.test(cleanEmail)) {
      return res.status(400).json({
        success: false,
        error: 'Please provide a valid email address.'
      });
    }

    const cleanSubject = typeof subject === 'string' ? subject.trim().slice(0, 150) : '';

    if (!message || typeof message !== 'string' || message.trim().length < 10 || message.trim().length > 3000) {
      return res.status(400).json({
        success: false,
        error: 'Message content must be between 10 and 3000 characters.'
      });
    }

    // 3. Success response (credentials are never exposed to the client)
    return res.status(200).json({
      success: true,
      message: 'Thank you! Your message has been received securely.'
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      error: 'An internal error occurred while processing your message.'
    });
  }
}
