const express = require('express');
const AuthController = require('../controller/AuthController');
const { AuthCheck } = require('../middleware/auth');
const router = express.Router();


router.post('/register',AuthController.register)
router.post('/verify',AuthController.verifyAccount)
router.post('/login',AuthController.login)
router.post('/reset-password-link',AuthController.resetPasswordLink)
router.post('/reset-password/:id/:token',AuthController.resetPassword);
//router.get('/dashboard',AuthCheck,AuthController.dashboard)

router.all('/*',AuthCheck)
router.get('/dashboard',AuthController.dashboard)
router.post('/update/password',AuthController.updatePassword)


module.exports = router