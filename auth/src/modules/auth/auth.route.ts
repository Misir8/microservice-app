import express from "express";
import {login, logout, refreshToken, register, requestPasswordReset, resetPassword} from "./auth.controller";
import {authorize} from "../../middleware/auth.middleware";

const authRouter = express.Router();

authRouter.post('/login', login);
authRouter.post('/register', register);
authRouter.post('/refresh', authorize, refreshToken);
authRouter.delete('/logout', authorize, logout);
authRouter.post('/requestReset', authorize, requestPasswordReset);
authRouter.post('/passwordReset', resetPassword);

export default authRouter;
