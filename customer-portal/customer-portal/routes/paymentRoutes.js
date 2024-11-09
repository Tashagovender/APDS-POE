const express = require('express');
const Transaction = require('../models/Transaction');
const router = express.Router();
const authMiddleware = require('../middleware/auth');

// payment route (customers make payment requests)
router.post('/pay', authMiddleware, async (req, res) => {
    const { amount, currency, payeeAccount, swiftCode } = req.body; // data required 

    // validate required fields
    if (!amount || !currency || !payeeAccount || !swiftCode) {
        return res.status(400).json({ message: 'All fields are required' });
    }

    try {
        // create new transaction in db 
        const newTransaction = new Transaction({
            customerId: req.customerId, 
            amount,
            currency,
            payeeAccount,
            swiftCode,
            status: 'pending' // default status, wait for verification from employee
        });

        await newTransaction.save();
        // if successful 
        res.status(201).json({ message: 'Payment transaction successful', transaction: newTransaction });
    } catch (error) {
        // if unsuccessful
        res.status(500).json({ message: 'Payment transaction failed', error: error.message });
    }
});

module.exports = router;
