import express from "express";
import users from "./database";
import { v4 as uuidv4 } from "uuid";
import jwt from "jsonwebtoken";
import { compare, hash } from "bcryptjs";

const app = express();
app.use(express.json());
const PORT = 3000;

const verifyEmailExistsMiddleware = (req, res, next) => {
  const foundEmail = users.find(({ email }) => email == req.body.email);

  if (foundEmail) {
    return res.status(409).json({ message: "E-mail already registered" });
  }

  return next();
};

const verifyAuthorizationMiddleware = (req, res, next) => {
  let token = req.headers.authorization;

  if (!token) {
    res.status(401).json({
      message: "Missing authorization headers",
    });
  }

  token = token.split(" ")[1];

  jwt.verify(token, "SECRET_KEY", (error, decoded) => {
    if (error) {
      return res.status(401).json({
        message: "Missing authorization headers",
      });
    }

    req.user = {
      id: decoded.sub,
      isAdm: decoded.isAdm,
    };

    return next();
  });
};

const verifyIsAdmMiddleware = (req, res, next) => {
  const userIsAdm = req.user.isAdm;
  const paramsId = req.params.id;
  const userId = req.user.id;

  if (paramsId) {
    if (userId !== paramsId) {
      if (!userIsAdm) {
        return res.status(403).json({
          message: "missing admin permissions",
        });
      } else {
        return next();
      }
    } else {
      return next();
    }
  }

  if (!userIsAdm) {
    return res.status(403).json({
      message: "missing admin permissions",
    });
  }

  return next();
};

const createUserController = async (req, res) => {
  const { email, name, password, isAdm } = req.body;

  const [status, user] = await createUserService(email, name, password, isAdm);

  return res.status(status).json(user);
};

const listUsersController = (req, res) => {
  const userList = listUsersService();

  return res.json(userList);
};

const loginController = async (req, res) => {
  const { email, password } = req.body;

  const token = await loginService(email, password);

  return res.json(token);
};

const getUserProfileController = (req, res) => {
  const userId = req.user.id;

  const userProfile = getUserProfileService(userId);

  return res.json(userProfile);
};

const updateUserController = (req, res) => {
  const idToUpdate = req.params.id;

  const payload = {
    updateOn: new Date(),
    name: req.body.name,
    email: req.body.email,
  };

  const updatedProfile = updateUserService(idToUpdate, payload);

  return res.json(updatedProfile);
};

const deleteUserController = (req, res) => {
  const idToDelete = req.params.id;

  const [status, message] = deleteUserService(idToDelete);

  return res.status(status).json(message);
};

const createUserService = async (email, name, password, isAdm) => {
  const date = new Date();
  const hashedPassword = await hash(password, 10);

  const newUser = {
    uuid: uuidv4(),
    createdOn: date,
    updateOn: date,
    name,
    email,
    isAdm,
  };

  const newUserRegister = { ...newUser, password: hashedPassword };

  users.push(newUserRegister);

  return [201, newUser];
};

const listUsersService = () => {
  return users;
};

const loginService = async (email, password) => {
  const foundUser = users.find((user) => user.email === email);

  if (!foundUser) {
    return [409, { message: "Invalid email or password." }];
  }

  const passwordMatch = await compare(password, foundUser.password);

  if (!passwordMatch) {
    return [409, { message: "Invalid email or password." }];
  }

  const token = jwt.sign({ email, isAdm: foundUser.isAdm }, "SECRET_KEY", {
    expiresIn: "24h",
    subject: foundUser.uuid,
  });

  return { token };
};

const getUserProfileService = (userId) => {
  const { uuid, createdOn, updateOn, name, email, isAdm } = users.find(
    ({ uuid }) => uuid == userId
  );
  const profileNoPass = {
    uuid,
    createdOn,
    updateOn,
    name,
    email,
    isAdm,
  };

  return profileNoPass;
};

const updateUserService = (idToUpdate, payload) => {
  const profileToUpdateIndex = users.findIndex(
    ({ uuid }) => uuid == idToUpdate
  );

  users[profileToUpdateIndex] = { ...users[profileToUpdateIndex], ...payload };

  const updatedUser = users[profileToUpdateIndex];

  const updatedUserResp = {
    uuid: updatedUser.uuid,
    createdOn: updatedUser.createdOn,
    updateOn: updatedUser.updateOn,
    name: updatedUser.name,
    email: updatedUser.email,
    isAdm: updatedUser.isAdm,
  };

  return updatedUserResp;
};

const deleteUserService = (idToDelete) => {
  const indexToDelete = users.findIndex(({ uuid }) => uuid == idToDelete);
  users.splice(indexToDelete, 1);

  return [204, {}];
};

app.post("/users", verifyEmailExistsMiddleware, createUserController);
app.get(
  "/users",
  verifyAuthorizationMiddleware,
  verifyIsAdmMiddleware,
  listUsersController
);
app.post("/login", loginController);
app.get(
  "/users/profile",
  verifyAuthorizationMiddleware,
  getUserProfileController
);
app.patch(
  "/users/:id",
  verifyAuthorizationMiddleware,
  verifyIsAdmMiddleware,
  updateUserController
);
app.delete(
  "/users/:id",
  verifyAuthorizationMiddleware,
  verifyIsAdmMiddleware,
  deleteUserController
);

app.listen(PORT, () => console.log(`App rodando em http://localhost:${PORT}`));

export default app;
