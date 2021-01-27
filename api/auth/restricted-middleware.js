const e = require('express');
const jwt = require('jsonwebtoken');
const { jwtSecret } = require('../../config/secrets');

module.exports = (req, res, next) => {
    const token = req.headers.quthorization;
    if (token) {
        jwt.verify(token, jwtSecret, (err, decoded) => {
            if (err) {
                res.status(401).json('Please supply a valid token')
            } else {
                req.decodedJwt = decoded;
                next();
            }
        })
    } else {
        res.status(401).json("You must have a token to do that");
    }
    next();
}