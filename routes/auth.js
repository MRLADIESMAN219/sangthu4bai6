var express = require("express");
var router = express.Router();
const path = require('path'); // Đã thêm thư viện path
let fs = require('fs');

let userController = require('../controllers/users');
let bcrypt = require('bcrypt');
let jwt = require('jsonwebtoken');
const { CheckLogin } = require("../utils/authHandler");

// 1. CHỨC NĂNG ĐĂNG KÝ
router.post('/register', async function (req, res, next) {
    try {
        let { username, password, email } = req.body;
        let newUser = await userController.CreateAnUser(
            username, password, email, "69b0ddec842e41e8160132b8"
        );
        res.send(newUser);
    } catch (error) {
        res.status(404).send(error.message);
    }
});

// 2. CHỨC NĂNG ĐĂNG NHẬP
router.post('/login', async function (req, res, next) {
    try {
        let { username, password } = req.body;
        let user = await userController.GetAnUserByUsername(username);
        
        if (!user) {
            res.status(404).send({ message: "thong tin dang nhap sai" });
            return;
        }
        
        if (user.lockTime > Date.now()) {
            res.status(404).send({ message: "ban dang bi ban" });
            return;
        }
        
        if (bcrypt.compareSync(password, user.password)) {
            user.loginCount = 0; // Đã sửa lỗi chỗ này
            await user.save();
            
            // Đọc Private Key và tạo Token với RS256
            let privateKey = fs.readFileSync(path.join(__dirname, '../private.pem'), 'utf8');
            let token = jwt.sign(
                { id: user._id }, 
                privateKey, 
                { algorithm: 'RS256', expiresIn: '1h' }
            );
            
            res.send(token);
        } else {
            user.loginCount++;
            if (user.loginCount == 3) {
                user.loginCount = 0;
                user.lockTime = Date.now() + 3600 * 1000; // Khóa 1 tiếng
            }
            await user.save();
            res.status(404).send({ message: "thong tin dang nhap sai" });
        }
    } catch (error) {
        res.status(404).send({ message: error.message });
    }
});

// 3. CHỨC NĂNG LẤY THÔNG TIN USER (/ME)
router.get('/me', CheckLogin, function(req, res, next){
    res.send(req.user);
});

// 4. CHỨC NĂNG ĐỔI MẬT KHẨU
router.post('/change-password', CheckLogin, async function (req, res, next) {
    try {
        let { oldpassword, newpassword } = req.body;

        if (!newpassword || newpassword.length < 6) {
            return res.status(400).send({
                message: "Mật khẩu mới không hợp lệ (phải có ít nhất 6 ký tự)"
            });
        }

        let user = req.user;

        if (!bcrypt.compareSync(oldpassword, user.password)) {
            return res.status(400).send({
                message: "Mật khẩu cũ không chính xác"
            });
        }

        let salt = bcrypt.genSaltSync(10);
        let hashedNewPassword = bcrypt.hashSync(newpassword, salt);
        
        user.password = hashedNewPassword;
        await user.save();

        res.send({ message: "Đổi mật khẩu thành công!" });

    } catch (error) {
        res.status(500).send({ message: error.message });
    }
});

module.exports = router;