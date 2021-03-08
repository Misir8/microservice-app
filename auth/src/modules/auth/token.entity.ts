import {Document, model, Schema, Types} from "mongoose";

export interface IToken extends Document{
    _id: Types.ObjectId
    token: string
}

const TokenSchema = new Schema<IToken>({
    token: { type: String },
});

export const Token =  model<IToken>("Token", TokenSchema);
