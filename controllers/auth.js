const User = require("../models/user");
const jwt = require("jsonwebtoken");
const { v4: uuid } = require('uuid');
const nodemailer = require('nodemailer');
const crypto = require('crypto');

exports.signup = async (req, res) => {
  const { name, email, password, role } = req.body;

  try {
    const user = await User.findOne({ email }).exec();
    if (user) {
      return res.status(400).json({
        error: "Email is taken",
      });
    }

   

    const newUser = new User({
      name,
      role,
      email,
      password,
     
    });

    await newUser.save();

    res.json({
      message: "Signup success! Please login",
     
    });
  } catch (error) {
    return res.status(400).json(error);
  }
};




exports.signin = (req, res) => {
  const { email, password } = req.body;

  // check if user exists
  User.findOne({ email }).exec((err, user) => {
    console.log(user);
    if (err || !user) {
      return res.status(400).json({
        error: "User with that email does not exist. Please signup",
      });
    }

    // authenticate
    if (!user.authenticate(password)) {
      return res.status(400).json({
        error: "Email and password do not match",
      });
    }
  // Check if the user is verified

    if (
      user.role === "admin" 
 
    ) {
      // Set the user object in the session
      req.session.user = {
        _id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
      };

      // Generate a JWT token
      const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, {
        expiresIn: "7d",
      });

      // Set the JWT token as a cookie
      res.cookie("token", token, {
        httpOnly: true,
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days in milliseconds
        
      });

      // Return the user details and token
      return res.json({
        token,
        user: {
          _id: user._id,
          name: user.name,
          email: user.email,
          role: user.role,
        },
      });
    } else {
      return res.status(400).json({
        error: "User not found",
      });
    }
  });
};


//reset password api by the token
exports.updatePassword = async (req, res) => {
  try {
    const { token, password, email } = req.body;
    const user = await User.findOne({
      email: email,
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: Date.now() },
    });

    if (!user) {
      return res
        .status(400)
        .json({ error: "User Not Found.Give Valid User Email." });
    }
    user.password = password; // Set the new password
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    user.salt = user.makeSalt(); // Generate a new salt for the user
    user.hashed_password = user.encryptPassword(password); // Encrypt the new password
    await user.save();
    // send email to the user to confirm that their password has been changed
    res.status(200).json({ message: "Password updated successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal server error" });
  }
};
