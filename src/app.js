import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";

const app = express();

// app.use(cors({
//     origin: process.env.CORS_ORIGIN,
//     credentials: true
// }))

const allowedOrigins = process.env.CORS_ORIGIN.split(",");

// CORS options ko configure karen
const corsOptions = {
    origin: (origin, callback) => {
        if (allowedOrigins.indexOf(origin) !== -1 || !origin) {
            callback(null, true);
        } else {
            callback(new Error("Not allowed by CORS"));
        }
    },
    credentials: true,
};

app.use(cors(corsOptions));

app.use(express.json({ limit: "32kb" }));
app.use(express.urlencoded({ extended: true, limit: "32kb" }));
app.use(express.static("public"));
// app.use(upload.any());
app.use(cookieParser());
// app.use(express.json())

// inmport routes
import userRouter from "./Routes/user.routes.js";

//routes declaration
app.use("/api/v1/users", userRouter);

export { app };
