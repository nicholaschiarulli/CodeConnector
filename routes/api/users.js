const express = require("express");
const router = express.Router();

const gravatar = require("gravatar");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const config = require("config");

//get validator from express for error checking
const { check, validationResult } = require("express-validator/check");

//bring in model for User
const User = require("../../models/User");
router.post(
  "/",
  [
    check("name", "Name is required")
      .not()
      .isEmpty(),
    check("email", "Valid email is required").isEmail(),
    check(
      "password",
      "Password with 8 or more characters is required"
    ).isLength({ min: 8 })
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, email, password } = req.body;

    //see if user exists
    try {
      let user = await User.findOne({ email });

      if (user) {
        return res
          .status(400)
          .json({ errors: [{ msg: "User already exists" }] });
      }
      //get users gravatar
      const avatar = gravatar.url(email, {
        s: "200",
        r: "pg",
        d: "mm"
      });

      //create the user with values
      user = new User({
        name,
        email,
        avatar,
        password
      });
      //encrypt password with bcrypt
      const salt = await bcrypt.genSalt(10);

      user.password = await bcrypt.hash(password, salt);

      //save the user in the database
      await user.save();

      //return jsonwebtoken so user gets logged in right away after registration

      //payload used by sign to determine user by id
      const payload = {
        user: {
          id: user.id //mongoose allows us to do .id instead of mongoDB _.id
        }
      };

      //sign token then send token back to the client
      jwt.sign(
        payload,
        config.get("jwtSecret"),
        { expiresIn: 3600 },
        (err, token) => {
          if (err) throw err;
          res.json({ token });
        }
      );
    } catch (err) {
      console.error(err.message);
      res.status(500).send("Server error");
    }
  }
);

module.exports = router;
