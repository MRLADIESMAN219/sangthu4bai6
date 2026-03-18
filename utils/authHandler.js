let userController = require('../controllers/users');
let jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

module.exports = {
    CheckLogin: async function (req, res, next) {
        try {
            // 1. Kiểm tra header Authorization
            if (!req.headers.authorization || !req.headers.authorization.startsWith("Bearer")) {
                res.status(401).send({
                    message: "ban chua dang nhap"
                });
                return;
            }

            let token = req.headers.authorization.split(" ")[1];

            // 2. Đọc Public Key từ thư mục gốc
            let publicKey = fs.readFileSync(path.join(__dirname, '../public.pem'), 'utf8');

            // 3. Giải mã Token bằng thuật toán RS256
            let result = jwt.verify(token, publicKey, { algorithms: ['RS256'] });

            // 4. Kiểm tra hạn của Token (Đã sửa lỗi Date.now -> Date.now())
            if (result.exp * 1000 < Date.now()) {
                res.status(401).send({
                    message: "token da het han"
                });
                return;
            }

            // 5. Tìm User
            let user = await userController.GetAnUserById(result.id);
            if (!user) {
                res.status(404).send({
                    message: "nguoi dung khong ton tai"
                });
                return;
            }

            // 6. Cho phép đi tiếp
            req.user = user;
            next();

        } catch (error) {
            res.status(401).send({
                message: "token khong hop le hoac ban chua dang nhap"
            });
        }
    }
}