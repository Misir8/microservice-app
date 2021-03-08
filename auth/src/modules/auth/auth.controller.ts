import {Request, Response} from "express";
import {User} from "./user.entity";
import jwt from 'jsonwebtoken';
import bcrypt from "bcrypt";
import {Token} from "./token.entity";
import {config} from "dotenv";
import * as crypto from "crypto";
import {VerifyToken} from "./verify-token.entity";
import {sendEmail} from "../../utils/mailer";
import {Types} from "mongoose";

config();
const {REFRESH_TOKEN_SECRET, ACCESS_TOKEN_SECRET, ORIGIN} = process.env;

export const register = async (req: Request, res: Response) => {
    try {
        const {email, password} = req.body;
        let user = await User.findOne({email});
        if (user) {
            return res.status(400).json({error: "Email already exists."});
        } else {
            const user = await new User({email, password});
            await user.save();
            const accessToken = await user.createAccessToken();
            const refreshToken = await user.createRefreshToken();

            return res.status(201).json({accessToken, refreshToken});
        }
    } catch (error) {
        return res.status(500).json({error: "Internal Server Error!"});
    }
}

export const login = async (req: Request, res: Response) => {
    try {
        const {email, password} = req.body;
        let user = await User.findOne({email});
        if (!user) {
            return res.status(404).json({error: "No user found!"});
        } else {
            let valid = await bcrypt.compare(password, user.password);
            if (valid) {
                const accessToken = await user.createAccessToken();
                const refreshToken = await user.createRefreshToken();

                return res.status(201).json({accessToken, refreshToken});
            } else {
                return res.status(401).json({error: "Invalid password!"});
            }
        }
    } catch (error) {
        return res.status(500).json({error: "Internal Server Error!"});
    }
}

export const refreshToken = async (req: Request, res: Response) => {
    try {
        const {refreshToken} = req.body;
        if (!refreshToken) {
            return res.status(403).json({error: "Access denied,token missing!"});
        } else {
            const tokenDoc = await Token.findOne({token: refreshToken});
            if (!tokenDoc) {
                return res.status(401).json({error: "Token expired!"});
            } else {
                const payload = jwt.verify(tokenDoc.token, REFRESH_TOKEN_SECRET as string);
                const accessToken = jwt.sign({user: payload}, ACCESS_TOKEN_SECRET as string, {
                    expiresIn: "10m",
                });
                return res.status(200).json({accessToken});
            }
        }
    } catch (error) {
        return res.status(500).json({error: "Internal Server Error!"});
    }
}

export const logout = async (req: Request, res: Response) => {
    try {
        const {refreshToken} = req.body;
        await Token.findOneAndDelete({token: refreshToken});
        return res.status(200).json({success: "User logged out!"});
    } catch (error) {
        return res.status(500).json({error: "Internal Server Error!"});
    }
};

export const requestPasswordReset = async (req: Request, res: Response) => {
    const {email} = req.body;
    const user = await User.findOne({email});

    if (!user) return res.status(404).json("User does not exists");
    let token = await VerifyToken.findOne({userId: user._id});
    if (token) await token.deleteOne();
    let resetToken = crypto.randomBytes(32).toString("hex");
    let salt = await bcrypt.genSalt(12);
    const hash = await bcrypt.hash(resetToken, salt);

    await new VerifyToken({
        userId: user._id,
        token: hash,
        createdAt: Date.now(),
    }).save();

    const link = `${ORIGIN}/api/auth/passwordReset?token=${resetToken}&id=${user._id}`;
    console.log(link)
    await sendEmail(user.email, "Password Reset Request", `<a href='${link}'>please reset token</a>`,
        `<a href='${link}'>please reset token</a>`);
    return res.status(200).json('success send message');
};

export const resetPassword = async (req: Request, res: Response) => {
    const {id, token} = req.query;
    const {password} = req.body;
    let passwordResetToken = await VerifyToken.findOne({userId: Types.ObjectId(id as string)});
    if (!passwordResetToken) {
        return res.status(400).json("Invalid or expired password reset token");
    }
    const isValid = await bcrypt.compare(token, passwordResetToken.token);
    if (!isValid) {
        return res.status(400).json("Invalid or expired password reset token");
    }
    const user = await User.findById({_id: Types.ObjectId(id as string)});
    if (!user) return res.status(401).json('User does not exists')
    let salt = await bcrypt.genSalt(12);
    const hash = await bcrypt.hash(password, salt);
    await User.updateOne(
        {email: user.email},
        {$set: {password: hash}},
        {new: true}
    );
    await sendEmail(
        user.email,
        "Password Reset Successfully",
        "Success reset",
        "<h1>Success reset password</h1>"
    );
    await passwordResetToken.deleteOne();
    return res.status(200).json('success send message');
};
