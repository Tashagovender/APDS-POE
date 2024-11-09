const express = require('express');
const bcrypt = require('bcryptjs'); // for hashing and salting
const jwt = require('jsonwebtoken'); // for tokens
const Customer = require('../models/Customer'); // data class customer
const { check, validationResult } = require('express-validator'); // import express-validator
const router = express.Router();

// register a new customer
router.post(
  '/register',
  [
    // input validation 
    //whitelisting using regex patterns
    check('fullName')
      .matches(/^[a-zA-Z\s]{3,25}$/) // Allows only letters and spaces, 2-50 characters
      .withMessage('Full Name must be 3-25 characters long and can only contain letters and spaces'),
    
    check('idNumber')
      .matches(/^\d{13}$/) // Allows exactly 13 digits
      .withMessage('ID Number must be exactly 13 digits'),

    check('accountNumber')
      .matches(/^\d{10}$/) // Allows exactly 10 digits
      .withMessage('Account Number must be exactly 10 digits'),

    check('password')
      .matches(/^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[\W_]).{7,}$/) // At least one uppercase, one lowercase, one number, one special character, at least 7 characters long
      .withMessage('Password must be at least 7 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character'),
  ],
  async (req, res) => {
    // for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { fullName, idNumber, accountNumber, password } = req.body;

    try {
      // hash password
      const hashedPassword = await bcrypt.hash(password, 10);

      // create new customer in db
      const newCustomer = new Customer({
        fullName,
        idNumber,
        accountNumber,
        password: hashedPassword, // Store hashed password
      });

      await newCustomer.save();
      // successful
      res.status(201).json({ message: 'Customer registered successfully' });
    } catch (error) {
      // unsuccessful
      res.status(500).json({ error: 'Registration failed' });
    }
  }
);

// login customer
router.post(
  '/login',
  [
    // input validation for login
    check('accountNumber')
      .matches(/^\d{10}$/) // Allows exactly 10 digits
      .withMessage('Account Number must be exactly 10 digits'),

    check('password')
      .matches(/^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[\W_]).{7,}$/) // Enforce same password rules as registration with regex patterns
      .withMessage('Password must be at least 7 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character'),
  ],
  async (req, res) => {
    // for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { accountNumber, password } = req.body;

    try {
      // find customer by account number
      const customer = await Customer.findOne({ accountNumber });
      if (!customer) return res.status(401).json({ message: 'Invalid credentials' });

      // compare passwords
      const isMatch = await bcrypt.compare(password, customer.password);
      if (!isMatch) return res.status(401).json({ message: 'Invalid credentials' });

      // get token for customer login
      const token = jwt.sign({ id: customer._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
      res.json({ token });
    } catch (error) {
      res.status(500).json({ error: 'Login failed' });
    }
  }
);

module.exports = router;
