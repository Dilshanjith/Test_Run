import Joi from "joi";

class User {
  constructor(id, email, firstName, lastName, password, balance = 0, isAdmin = false) {
    this.id = id;
    this.email = email;
    this.firstName = firstName;
    this.lastName = lastName;
    this.password = password;
    this.balance = balance;
    this.isAdmin = isAdmin;
  }

  // General validation for the user model
  validate = () => {
    const schema = Joi.object({
      id: Joi.string().uuid().required(),
      email: Joi.string().email().required(),
      firstName: Joi.string().required(),
      lastName: Joi.string().required(),
      balance: Joi.number().min(0).required(),
      isAdmin: Joi.boolean().required(),
    });

    return schema.validate({
      id: this.id,
      email: this.email,
      firstName: this.firstName,
      lastName: this.lastName,
      balance: this.balance,
      isAdmin: this.isAdmin,
    });
  };

  // Validation for signup - email, password, and name required
  validateSignup = () => {
    const schema = Joi.object({
      firstName: Joi.string().required(),
      lastName: Joi.string().required(),
      email: Joi.string().email().required(),
      password: Joi.string().min(6).required(), // Password length check
    });

    return schema.validate({
      email: this.email,
      password: this.password,
      firstName: this.firstName,
      lastName: this.lastName,
    });
  };

  // Validation for login - email and password required
  validateLogin = () => {
    const schema = Joi.object({
      email: Joi.string().email().required(),
      password: Joi.string().required(),
    });

    return schema.validate({
      email: this.email,
      password: this.password,
    });
  };

  // Validation for user ID
  validateId = () => {
    const schema = Joi.object({
      id: Joi.string().uuid().required(),
    });

    const validate = schema.validate({ id: this.id });

    if (validate.error) return validate.error.details[0].message;
  };
}

export default User;
