import {Document, model, Schema, Types} from "mongoose";

interface IVerifyTokenEntity extends Document{
    _id: Types.ObjectId;
    token: string;
    createdAt: Date;
}

const VerifyTokenSchema = new Schema<IVerifyTokenEntity>({
    userId: {
        type: Schema.Types.ObjectId,
        required: true,
        ref: "users",
    },
    token: {
        type: String,
        required: true,
    },
    createdAt: {
        type: Date,
        default: Date.now,
        expires: 3600,
    },
});
export const VerifyToken = model<IVerifyTokenEntity>("VerifyToken", VerifyTokenSchema);
