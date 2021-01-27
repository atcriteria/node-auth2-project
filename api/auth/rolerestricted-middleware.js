module.exports = role => (req,res,next) => {
    if (req.decodedJWT && req.decodedJWT.role === role) {
        next()
    } else {
        res.status(403).json('You are not permitted.')
    }
}