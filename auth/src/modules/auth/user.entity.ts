import {Document, model, Schema} from "mongoose";
import bcrypt from 'bcrypt';
import jwt, {SignOptions} from 'jsonwebtoken';
import {config} from "dotenv";
import {Token} from './token.entity';
config()

export interface IUser extends Document{
    _id: Schema.Types.ObjectId,
    email: string;
    password: string;
    createAccessToken(): Promise<string>;
    createRefreshToken(): Promise<IJwtToken>;
}

interface IJwtToken {
    payload: string | Buffer | object,
    secretOrPrivateKey: string | Buffer | {key: string | Buffer, passphrase: string},
    options?: SignOptions
}

const UserSchema = new Schema<IUser>({
    email: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    }
});


UserSchema.methods = {
    createAccessToken: async function () {
        try {
            let { _id, email } = this;
            return jwt.sign(
                {user: {_id, email}},
                process.env.ACCESS_TOKEN_SECRET || '',
                {
                    expiresIn: "10m",
                }
            );
        } catch (error) {
            console.error(error);
            return;
        }
    },
    createRefreshToken: async function () {
        try {
            let { _id, email } = this;
            let refreshToken = jwt.sign(
                { user: { _id, email } },
                process.env.REFRESH_TOKEN_SECRET || '',
                {
                    expiresIn: "1d",
                }
            );
            await new Token({ token: refreshToken }).save();
            return refreshToken;
        } catch (error) {
            console.error(error);
            return;
        }
    },
};

UserSchema.pre("save", async function (next) {
    try {
        let salt = await bcrypt.genSalt(12);
        this.password = await bcrypt.hash(this.password, salt);
    } catch (error) {
        console.error(error);
    }
    return next();
});

export const User = model<IUser>('user', UserSchema, 'users');
