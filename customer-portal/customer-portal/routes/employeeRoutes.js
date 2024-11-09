const express = require('express');
const bcrypt = require('bcryptjs'); // for hashing and salting
const jwt = require('jsonwebtoken'); // for tokens
const Employee = require('../models/Employee'); // Employee model
const { check, validationResult } = require('express-validator'); // import express-validator
const router = express.Router();

// Employee login route
router.post(
  '/login',
  [
    // Input validation for login
    check('employeeId')
      .matches(/^[a-zA-Z0-9]{8}$/) // Allows exactly 8 alphanumeric characters
      .withMessage('Employee ID must be exactly 8 characters long and alphanumeric.'),

    check('password')
      .matches(/^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[\W_]).{7,}$/) // Enforce password rules
      .withMessage(
        'Password must be at least 7 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character.'
      ),
  ],
  async (req, res) => {
    // For validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { employeeId, password } = req.body;

    try {
      // Find employee by ID
      const employee = await Employee.findOne({ employeeId });
      if (!employee) return res.status(401).json({ message: 'Invalid credentials' });

      // Compare passwords
      const isMatch = await bcrypt.compare(password, employee.password);
      if (!isMatch) return res.status(401).json({ message: 'Invalid credentials' });

      // Generate token for employee login
      const token = jwt.sign({ id: employee._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
      res.json({ token });
    } catch (error) {
      res.status(500).json({ error: 'Login failed' });
    }
  }
);

module.exports = router;
