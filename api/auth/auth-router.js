const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const router = require('express').Router();
const { jwtSecret } = require('../../config/secrets');
const Users = require('../users/users-model');
const { isValid } = require('../users/users-service');


router.post('/register', (req, res) => {
    const credentials = req.body;

    if (isValid(credentials)) {
        const rounds = process.env.BCRYPT_ROUNDS || 8;

        const hash = bcrypt.hashSync(credentials.password, rounds);
        credentials.password = hash;

        Users.add(credentials)
            .then(user => {
                res.status(201).json({ data: user });
            })
            .catch(err => {
                res.status(500).json({ message: err.message})
            });
    } else {
        res.status(400).json({
            message: "You must provide a username and password"
        });
    }
});

router.post('/login', (req, res) => {
    const { username, password } = req.body;

    if(isValid(req.body)) {
        Users.findBy({ username: username })
            .then(([user]) => {
                if (user && bcrypt.compareSync(password, user.password)) {
                    const token = generateToken(user);
                    res.status(200).json({ message: "Welcome", token});
                } else {
                    res.status(401).json({ message: "Invalid credentials"});
                }
            })
            .catch(err => {
                res.status(500).json({ message: err.message})
            })
    } else {
        res.status(400).json({
            message: "You must provide a username and password."
        });
    }
});

function generateToken(user){
    const payload = {
        subject: user.id,
        username: user.username,
        role: user.role,
    }
    const options = {
        expiresIn: '1d',
    }
    return jwt.sign(payload, jwtSecret, options);
}

module.exports = router;