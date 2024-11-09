const express = require('express');
const mongoose = require('mongoose'); 
const dotenv = require('dotenv');
const fs = require('fs'); // ssl setup 
const http = require('http'); 
const cors=require ('cors');
/* const xss = require('xss-clean'); // xss protection
const helmet = require('helmet');  // security headers
const rateLimit = require('express-rate-limit');  // ddos protection
const mongoSanitize = require('express-mongo-sanitize');  // nosql injection prevention
const hpp = require('hpp');  // http parameter pollution protection
const cookieParser = require('cookie-parser');  // cookies
const csrf = require('csurf');  // csrf protection
const path = require('path');*/
const customerRoutes = require('./routes/customerRoutes'); // import customer routes
const paymentRoutes = require('./routes/paymentRoutes');  // import payment routes

dotenv.config();

const app = express();
app.use(express.json()); // middleware
app.use(cors());

/* security middlewares
app.use(xss());
app.use(helmet()); 
app.use(mongoSanitize());
app.use(hpp()); 
app.use(cookieParser());

// csrf protection middleware
const csrfProtection = csrf({ cookie: true });
app.use(csrfProtection);

// send csrf token to the frontend via cookie
app.use((req, res, next) => {
    res.cookie('XSRF-TOKEN', req.csrfToken());
    next();
});

// rate limiter to protect against ddos attacks
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests
    message: 'Too many requests from this IP, please try again later',
});
app.use(limiter); */

// mongoDB connection
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.log('MongoDB connection error:', err));

// for the customer routes (reg and login)
app.use('/api/customers', customerRoutes);
// for the payment routes (transactions)
app.use('/api', paymentRoutes);

//load SSL certificate and private key
const sslOptions = {
  key: fs.readFileSync('server.key'),
  cert: fs.readFileSync('server.cert')
}; 

const PORT = process.env.PORT || 5000;
// start https server
http.createServer(app).listen(PORT, () => {
  console.log(`HTTP server running on port ${PORT}`); 
});
