const express = require('express');
const connection = require('../connection');
const router = express.Router();

const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
require('dotenv').config();
var auth = require('../services/authentication');
var checkRole = require('../services/checkRole');


// SignUp Api

router.post('/signup', (req, res) => {
    let user = req.body;
    query = "select email,password,role,status from user where email=?"
    connection.query(query, [user.email], (err, results) => {
        if (!err) {
            if (results.length <= 0) {
                query = "insert into user(name,contactNumber,email,password,status,role) values(?,?,?,?,'false','user')";
                connection.query(query, [user.name, user.contactNumber, user.email, user.password], (err, results) => {
                    if (!err) {
                        return res.status(200).json({ message: "Successfully Registered" });
                    }
                    else {
                        return res.status(500).json(err);
                    }
                })
            }
            else {
                return res.status(400).json({ message: "Email Already Exist." });
            }
        }
        else {
            return res.status(500).json(err);
        }

    })

})

// Login Api

router.post('/login', (req, res) => {
    const user = req.body;
    query = "select email,password,role,status from user where email=?";
    connection.query(query, [user.email], (err, results) => {
        if (!err) {
            if (results.length <= 0 || results[0].password != user.password) {
                return res.status(401).json({ message: "Incorrect username or password" });
            }
            else if (results[0].status === 'false') {
                return res.status(401).json({ message: "Wait For Admin Approvel" });
            }
            else if (results[0].password == user.password) {
                const response = { email: results[0].email, role: results[0].role }
                const accessToken = jwt.sign(response, process.env.ACCESS_TOKEN, { expiresIn: '8hr' })
                res.status(200).json({ token: accessToken });
            }
            else {
                return res.status(400).json({ message: "Someting went wrong. please try again later" })
            }
        }
        else {
            return res.status(500).json(err);
        }
    })
})


// Forgot Password Api

var transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL,
        pass: process.env.PASSWORD
    }
})

router.post('/forgotPassword', (req, res) => {
    const user = req.body;
    query = "select email,password from user where email=?";
    connection.query(query, [user.email], (err, results) => {
        if (!err) {
            if (results.length <= 0) {
                return res.status(200).json({ message: "Password sent sucessfully your email." })
            }
            else {
                var mailOption = {
                    from: process.env.EMAIL,
                    to: results[0].email,
                    subject: 'Password By Motto Cafe APP',
                    html: '<p><b>Your login Details for Motto Cafe App</b><br><b>Email: </b>' + results[0].email + '<br><b>Password : </b>' + results[0].passwords + '<br><a href="http://localhost:4200">Click Here to login</a></p>'
                };
                transporter.sendMail(mailOption, function (error, info) {
                    if (error) {
                        console.log(error);
                    }
                    else {
                        console.log('Email Sent : ' + info.response);
                    }
                });
                return res.status(200).json({ message: "Password sent sucessfully your email." })
            }
        }
        else {
            return res.status(500).json(err);
        }
    })
})

// Get All User Api
router.get('/get', auth.authenticateToken, checkRole.checkRole, (req, res) => {
    var query = "select id,name,email,contactNumber,status from user where role='user'";
    connection.query(query, (err, results) => {
        if (!err) {
            return res.status(200).json(results);
        }
        else {
            return res.status(500).json(err);
        }
    })
})

// Update in User Api
router.patch('/update', auth.authenticateToken, checkRole.checkRole, (req, res) => {
    let user = req.body;
    var query = "update user set status=? where id=?";
    connection.query(query, [user.status, user.id], (err, results) => {
        if (!err) {
            if (results.affectedRows == 0) {
                return res.status(404).json({ message: "User id does not exist" });
            }
            return res.status(200).json({ message: "User Updated Successfully" });
        }
        else {
            return res.status(500).json(err);
        }
    })
})

// Check Token Api
router.get('/checkToken', auth.authenticateToken, (req, res) => {
    return res.status(200).json({ message: "true" });
})

// Changes Password Api
router.post('/changePassword', auth.authenticateToken, (req, res) => {
    const user = req.body;
    const email = res.locals.email;
    var query = "select *from user where email=? and password=?";
    connection.query(query, [email, user.oldpassword], (err, results) => {
        if (!err) {
            if (results.length <= 0) {
                return res.status(400).json({ message: "Incorrect Old Password" });
            }
            else if (results[0].password == user.oldpassword) {
                query = "update user set password=? where email=?";
                connection.query(query, [user.newpassword, email], (err, result) => {
                    if (!err) {
                        return res.status(200).json({ message: "Password update Successfully." })
                    }
                    else {
                        return res.status(500).json(err);
                    }
                })

            }
            else {
                return res.status(400).json({ message: "Something went wrong. please try again later" });
            }
        }
        else {
            return res.status(500).json(err);
        }
    })

})


module.exports = router;