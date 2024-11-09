// verification of token 
const jwt = require('jsonwebtoken');

const authMiddleware = (req, res, next) => { 
    const token = req.header('Authorization').replace('Bearer ', ''); // token is in the authorization header
    if (!token) return res.status(401).json({ message: 'Access denied. No token provided.' });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET); // verify token
        req.customerId = decoded.id; // attach customer id from the tokin to the request
        console.log('Authenticated customer:', req.customerId);  // to check the customer id
        next();
    } catch (error) {
        res.status(400).json({ message: 'Invalid token' }); // error handling
    }
};

module.exports = authMiddleware;
