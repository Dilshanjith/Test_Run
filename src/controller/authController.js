import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { v4 as uuidv4 } from "uuid";
import userRepository from "../repositories/userRepository.js";
import HttpStatus from "../enums/httpStatus.js";
import User from "../models/user.js";
import dotenv from "dotenv";

// Load environment variables
dotenv.config();

const user = new User(null, null, null, null, null);

const signup = async (req, res) => {
  try {
    const { firstName, lastName, email, password } = req.body;

    // Validate email format using regular expression
    const emailPattern = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}$/;
    if (!emailPattern.test(email)) {
      return res.status(HttpStatus.BAD_REQUEST).json({
        message: "Please enter a valid email address.",
      });
    }

    // Check if the user already exists
    const existingUser = await userRepository.getUserByEmail(email);
    if (existingUser) {
      return res.status(HttpStatus.BAD_REQUEST).json({
        message: "User already exists",
      });
    }

    // Generate user ID and set values
    user.id = uuidv4();
    user.firstName = firstName;
    user.lastName = lastName;
    user.email = email;
    user.password = password;
    const result = user.validateSignup();
    if (result.error) {
      return res.status(HttpStatus.BAD_REQUEST).json({
        message: result.error.details[0].message,
      });
    }

    // Hash the password before storing it
    const hashedPassword = bcrypt.hashSync(password, 10);
    user.password = hashedPassword;

    // Create the user
    const userCreated = await userRepository.createUser(user);
    if (!userCreated) {
      throw new Error();
    }

    return res
      .status(HttpStatus.CREATED)
      .json({ message: "User created successfully" });
  } catch (error) {
    return res
      .status(HttpStatus.INTERNAL_SERVER_ERROR)
      .json({ message: "An error occurred", error: error.message });
  }
};

const login = async (req, res) => {
  const { email, password } = req.body;
  user.email = email;
  user.password = password;

  const result = user.validateLogin();
  if (result.error)
    return res
      .status(HttpStatus.BAD_REQUEST)
      .send(result.error.details[0].message);

  try {
    const existingUser = await userRepository.getUserByEmail(email);
    if (!existingUser) {
      return res
        .status(HttpStatus.BAD_REQUEST)
        .json({ message: "Invalid email or password" });
    }

    const validatePassword = bcrypt.compareSync(
      password,
      existingUser.password
    );
    if (!validatePassword) {
      return res
        .status(HttpStatus.BAD_REQUEST)
        .json({ message: "Invalid email or password" });
    }

    const { password: userPassword, ...userWithoutPassword } = existingUser;

    // Get the JWT private key from the config
    const jwtPrivateKey = process.env.JWT_PRIVATE_KEY;

    if (!jwtPrivateKey) {
      return res
        .status(HttpStatus.INTERNAL_SERVER_ERROR)
        .json({ message: "JWT private key not set" });
    }

    let token = jwt.sign({ user: userWithoutPassword }, jwtPrivateKey, {
      expiresIn: "7d",
    });

    return res
      .status(HttpStatus.OK)
      .json({ data: userWithoutPassword, token: token });
  } catch (error) {
    return res
      .status(HttpStatus.INTERNAL_SERVER_ERROR)
      .json({ message: "An error occurred", error: error.message });
  }
};

export default { signup, login };
