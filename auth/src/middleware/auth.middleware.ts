import jwt from "jsonwebtoken";
import {NextFunction, Request, Response} from "express";

const privateKey = process.env.ACCESS_TOKEN_SECRET;

interface UserPayload {
    id: string;
    email: string;
}

declare global {
    namespace Express {
        interface Request {
            user?: UserPayload;
        }
    }
}

export const authorize = (req: Request, res: Response, next: NextFunction) => {
    const token = req.get("x-auth-token");
    if (!token) {
        return res.status(401).json({error: "Access denied, token missing!"});
    } else {
        try {
            const payload = jwt.verify(token, privateKey as string) as
                { user: UserPayload };
            req.user = payload.user;
            next();
        } catch (error) {
            if (error.name === "TokenExpiredError") {
                return res
                    .status(401)
                    .json({error: "Session timed out,please login again"});
            } else if (error.name === "JsonWebTokenError") {
                return res
                    .status(401)
                    .json({error: "Invalid token,please login again!"});
            } else {
                return res.status(400).json({error});
            }
        }
    }
};
