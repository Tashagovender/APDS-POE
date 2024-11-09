// model class for customer data 
const mongoose = require('mongoose');

const customerSchema = new mongoose.Schema({
    fullName: { type: String, required: true },
    idNumber: { type: String, required: true, unique: true },
    accountNumber: { type: String, required: true, unique: true },
    password: { type: String, required: true },
});

const Customer = mongoose.model('Customer', customerSchema);
module.exports = Customer;
