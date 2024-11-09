// model class for transaction data 
const mongoose = require('mongoose');

const transactionSchema = new mongoose.Schema({
    customerId: { type: mongoose.Schema.Types.ObjectId, ref: 'Customer', required: true },
    amount: { type: Number, required: true },
    currency: { type: String, required: true },
    payeeAccount: { type: String, required: true },
    swiftCode: { type: String, required: true },
    status: { type: String, enum: ['pending', 'verified', 'failed'], default: 'pending' }, // New status field
    createdAt: { type: Date, default: Date.now }
});

const Transaction = mongoose.model('Transaction', transactionSchema);
module.exports = Transaction;
