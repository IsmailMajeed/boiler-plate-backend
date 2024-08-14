import { Router } from "express";
import { upload } from "../middlewares/multer.middleware.js";
import { verifyJWT } from "../middlewares/auth.middleware.js";
import {
    registerUser,
    loginUser,
    logoutUser,
    changeCurrentPassword,
} from "../controllers/user.controller.js";


const router = Router()

router.route("/register").post(upload.single("avatar"), registerUser)
router.route("/login").post(upload.single("avatar"), loginUser)
router.route("/logout").post(verifyJWT, logoutUser)
router.route("/change-password").patch(verifyJWT, upload.any(), changeCurrentPassword)

export default router