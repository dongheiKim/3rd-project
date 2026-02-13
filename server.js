const express = require("express");
const jsonServer = require("json-server");
const jwt = require("jsonwebtoken");
const path = require("path");
const multer = require("multer");
const fs = require("fs");
const swaggerUi = require("swagger-ui-express");
const swaggerSpec = require("./swagger");

const app = express();
const PORT = 3000;

// ============================================
// JWT 설정
// ============================================
const JWT_CONFIG = {
  ACCESS_TOKEN_SECRET:
    process.env.ACCESS_TOKEN_SECRET || "your-access-token-secret-key",
  REFRESH_TOKEN_SECRET:
    process.env.REFRESH_TOKEN_SECRET || "your-refresh-token-secret-key",
  ACCESS_TOKEN_EXPIRES_IN: "1h", // 1시간
  REFRESH_TOKEN_EXPIRES_IN: "1d", // 1일
  // ACCESS_TOKEN_EXPIRES_IN: "1m", // 1분
  // REFRESH_TOKEN_EXPIRES_IN: "1h", // 1시간
};

// ============================================
// json-server 설정
// ============================================
const dbPath = path.join(__dirname, "db.json");
const router = jsonServer.router(dbPath);
const middlewares = jsonServer.defaults();

// ============================================
// 유틸리티 함수
// ============================================

// 이메일 형식 검증
function isValidEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

// accountname 형식 검증 (영문, 숫자, 밑줄, 마침표만)
function isValidAccountname(accountname) {
  const accountnameRegex = /^[a-zA-Z0-9_.]+$/;
  return accountnameRegex.test(accountname);
}

// 고유 ID 생성
function generateId() {
  return Date.now().toString() + Math.random().toString(36).substr(2, 9);
}

// JWT 토큰 생성 함수
function generateToken(user, tokenType = "access") {
  const isAccessToken = tokenType === "access";

  const payload = isAccessToken
    ? {
        _id: user._id,
        email: user.email,
        accountname: user.accountname,
      }
    : {
        _id: user._id,
        email: user.email,
      };

  const secret = isAccessToken
    ? JWT_CONFIG.ACCESS_TOKEN_SECRET
    : JWT_CONFIG.REFRESH_TOKEN_SECRET;

  const expiresIn = isAccessToken
    ? JWT_CONFIG.ACCESS_TOKEN_EXPIRES_IN
    : JWT_CONFIG.REFRESH_TOKEN_EXPIRES_IN;

  return jwt.sign(payload, secret, { expiresIn });
}

// JWT 토큰 검증 함수
function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_CONFIG.ACCESS_TOKEN_SECRET);
  } catch (error) {
    return null;
  }
}

// Refresh 토큰 검증 함수
function verifyRefreshToken(token) {
  try {
    return jwt.verify(token, JWT_CONFIG.REFRESH_TOKEN_SECRET);
  } catch (error) {
    return null;
  }
}

// ============================================
// Multer 설정 (이미지 업로드)
// ============================================

// uploadFiles 디렉토리 확인 및 생성
const uploadDir = path.join(__dirname, "uploadFiles");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Multer storage 설정
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "uploadFiles/");
  },
  filename: function (req, file, cb) {
    const timestamp = Date.now();
    const ext = path.extname(file.originalname);
    cb(null, `${timestamp}${ext}`);
  },
});

// 파일 필터 (이미지만 허용)
const fileFilter = (req, file, cb) => {
  const allowedTypes = /jpeg|jpg|png|gif|webp/;
  const extname = allowedTypes.test(
    path.extname(file.originalname).toLowerCase()
  );
  const mimetype = allowedTypes.test(file.mimetype);

  if (extname && mimetype) {
    cb(null, true);
  } else {
    cb(new Error("이미지 파일만 업로드 가능합니다."));
  }
};

// Multer 인스턴스 생성
const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB 제한
  },
});

// ============================================
// 미들웨어 설정
// ============================================
app.use(middlewares); // json-server 기본 미들웨어 (CORS, static, logger 등)
app.use(express.json()); // JSON 파싱
app.use("/uploadFiles", express.static(path.join(__dirname, "uploadFiles"))); // 업로드된 이미지 정적 제공

// ============================================
// API 라우터 설정
// ============================================
const apiRouter = express.Router();

// ============================================
// 커스텀 라우트 (json-server 라우터보다 먼저 정의)
// ============================================

/**
 * POST /api/image/uploadfile - 단일 이미지 업로드 API
 *
 * Content-Type: multipart/form-data
 * Form Data:
 * - image: File (이미지 파일)
 *
 * Response:
 * {
 *   "filename": "업로드된 파일명"
 * }
 */
apiRouter.post("/image/uploadfile", upload.single("image"), (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        message: "이미지를 업로드해주세요.",
      });
    }

    // 업로드된 파일 정보 반환
    res.status(200).json({
      fieldname: req.file.fieldname,
      originalname: req.file.originalname,
      encoding: req.file.encoding,
      mimetype: req.file.mimetype,
      destination: req.file.destination,
      filename: req.file.filename,
      path: req.file.path,
      size: req.file.size,
    });
  } catch (error) {
    console.error("이미지 업로드 오류:", error);
    res.status(500).json({
      message: "서버 오류가 발생했습니다.",
    });
  }
});

/**
 * POST /api/image/uploadfiles - 다중 이미지 업로드 API
 *
 * Content-Type: multipart/form-data
 * Form Data:
 * - image: File[] (이미지 파일들, 최대 10개)
 *
 * Response:
 * [
 *   {
 *     "filename": "업로드된 파일명1"
 *   },
 *   {
 *     "filename": "업로드된 파일명2"
 *   }
 * ]
 */
apiRouter.post("/image/uploadfiles", upload.array("image", 10), (req, res) => {
  try {
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({
        message: "이미지를 업로드해주세요.",
      });
    }

    // 업로드된 파일들 정보 반환
    const filesInfo = req.files.map((file) => ({
      fieldname: file.fieldname,
      originalname: file.originalname,
      encoding: file.encoding,
      mimetype: file.mimetype,
      destination: file.destination,
      filename: file.filename,
      path: file.path,
      size: file.size,
    }));

    res.status(200).json(filesInfo);
  } catch (error) {
    console.error("이미지 업로드 오류:", error);
    res.status(500).json({
      message: "서버 오류가 발생했습니다.",
    });
  }
});

/**
 * POST /api/user - 회원가입 API
 *
 * Request Body:
 * {
 *   "user": {
 *     "username": String (required),
 *     "email": String (required),
 *     "password": String (required, min 6 chars),
 *     "accountname": String (required, alphanumeric + _ . only),
 *     "intro": String (optional),
 *     "image": String (optional)
 *   }
 * }
 */
apiRouter.post("/user", (req, res) => {
  try {
    const { user } = req.body;

    // 1. 필수 입력사항 체크
    if (
      !user ||
      !user.username ||
      !user.email ||
      !user.password ||
      !user.accountname
    ) {
      return res.status(400).json({
        message: "필수 입력사항을 입력해주세요.",
      });
    }

    // 2. 비밀번호 길이 체크
    if (user.password.length < 6) {
      return res.status(400).json({
        message: "비밀번호는 6자 이상이어야 합니다.",
      });
    }

    // 3. 이메일 형식 체크
    if (!isValidEmail(user.email)) {
      return res.status(400).json({
        message: "잘못된 이메일 형식입니다.",
      });
    }

    // 4. accountname 형식 체크
    if (!isValidAccountname(user.accountname)) {
      return res.status(400).json({
        message: "영문, 숫자, 밑줄, 마침표만 사용할 수 있습니다.",
      });
    }

    // json-server의 lowdb 인스턴스를 통한 DB 접근
    const db = router.db; // json-server의 db 인스턴스 사용

    // 5. 이메일 중복 체크
    const existingEmail = db.get("users").find({ email: user.email }).value();
    if (existingEmail) {
      return res.status(400).json({
        message: "이미 가입된 이메일 주소입니다.",
      });
    }

    // 6. accountname 중복 체크
    const existingAccountname = db
      .get("users")
      .find({ accountname: user.accountname })
      .value();
    if (existingAccountname) {
      return res.status(400).json({
        message: "이미 사용중인 계정 ID입니다.",
      });
    }

    // 새 사용자 생성
    const newUser = {
      _id: generateId(),
      username: user.username,
      email: user.email,
      accountname: user.accountname,
      intro: user.intro || "",
      image: user.image || "",
      password: user.password, // 실제 프로덕션에서는 bcrypt 등으로 해시화 필요
    };

    // DB에 사용자 추가 (json-server의 lowdb 체인 사용)
    db.get("users").push(newUser).write();

    // 성공 응답 (password 제외)
    const { password, ...userResponse } = newUser;
    res.status(201).json({
      message: "회원가입 성공",
      user: userResponse,
    });
  } catch (error) {
    console.error("회원가입 오류:", error);
    res.status(500).json({
      message: "서버 오류가 발생했습니다.",
    });
  }
});

/**
 * POST /api/user/signin - 로그인 API
 *
 * Request Body:
 * {
 *   "user": {
 *     "email": String (required),
 *     "password": String (required)
 *   }
 * }
 */
apiRouter.post("/user/signin", (req, res) => {
  try {
    const { user } = req.body;

    // 1. 입력값 검증
    const hasEmail = user && user.email;
    const hasPassword = user && user.password;

    // email과 password 둘 다 없을 때
    if (!hasEmail && !hasPassword) {
      return res.status(400).json({
        message: "이메일 또는 비밀번호를 입력해주세요.",
      });
    }

    // email만 없을 때
    if (!hasEmail) {
      return res.status(400).json({
        message: "이메일을 입력해주세요.",
      });
    }

    // password만 없을 때
    if (!hasPassword) {
      return res.status(400).json({
        message: "비밀번호를 입력해주세요.",
      });
    }

    // json-server의 lowdb 인스턴스를 통한 DB 접근
    const db = router.db;

    // 2. 이메일로 사용자 찾기
    const foundUser = db.get("users").find({ email: user.email }).value();

    // 3. 사용자가 없거나 비밀번호가 일치하지 않을 때
    if (!foundUser || foundUser.password !== user.password) {
      return res.status(422).json({
        message: "이메일 또는 비밀번호가 일치하지 않습니다.",
        status: 422,
      });
    }

    // 4. 로그인 성공 - JWT 토큰 생성
    const accessToken = generateToken(foundUser, "access");
    const refreshToken = generateToken(foundUser, "refresh");

    // 5. 성공 응답 (password 제외, accessToken과 refreshToken 포함)
    res.status(200).json({
      user: {
        _id: foundUser._id,
        username: foundUser.username,
        email: foundUser.email,
        accountname: foundUser.accountname,
        image: foundUser.image,
        accessToken: accessToken,
        refreshToken: refreshToken,
      },
    });
  } catch (error) {
    console.error("로그인 오류:", error);
    res.status(500).json({
      message: "서버 오류가 발생했습니다.",
    });
  }
});

/**
 * POST /api/user/refresh - Refresh Token으로 Access Token 재발급 API
 *
 * Request Body:
 * {
 *   "refreshToken": String (required)
 * }
 *
 * Response:
 * {
 *   "accessToken": "새로운 access token",
 *   "refreshToken": "새로운 refresh token (optional)"
 * }
 */
apiRouter.post("/user/refresh", (req, res) => {
  try {
    const { refreshToken } = req.body;

    // 1. Refresh token 존재 여부 확인
    if (!refreshToken) {
      return res.status(400).json({
        message: "Refresh token이 필요합니다.",
      });
    }

    // 2. Refresh token 검증
    const decoded = verifyRefreshToken(refreshToken);

    if (!decoded) {
      return res.status(401).json({
        message: "유효하지 않거나 만료된 refresh token입니다.",
      });
    }

    // 3. 사용자 정보 조회
    const db = router.db;
    const foundUser = db.get("users").find({ _id: decoded._id }).value();

    if (!foundUser) {
      return res.status(404).json({
        message: "사용자를 찾을 수 없습니다.",
      });
    }

    // 4. 새로운 access token 생성
    const newAccessToken = generateToken(foundUser, "access");

    // 5. 새로운 refresh token도 함께 생성 (refresh token rotation)
    const newRefreshToken = generateToken(foundUser, "refresh");

    // 6. 성공 응답
    res.status(200).json({
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
    });
  } catch (error) {
    console.error("Refresh token 처리 오류:", error);
    res.status(500).json({
      message: "서버 오류가 발생했습니다.",
    });
  }
});

/**
 * GET /api/user/myinfo - 내 정보 조회 API
 *
 * Headers:
 * {
 *   "Authorization": "Bearer {accessToken}"
 * }
 */
apiRouter.get("/user/myinfo", (req, res) => {
  try {
    // 1. Authorization 헤더에서 토큰 추출
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        message: "인증 토큰이 필요합니다.",
      });
    }

    const token = authHeader.substring(7); // "Bearer " 제거

    // 2. 토큰 검증
    const decoded = verifyToken(token);

    if (!decoded) {
      return res.status(401).json({
        message: "유효하지 않은 토큰입니다.",
      });
    }

    // 3. DB에서 사용자 정보 조회
    const db = router.db;
    const user = db.get("users").find({ _id: decoded._id }).value();

    if (!user) {
      return res.status(404).json({
        message: "사용자를 찾을 수 없습니다.",
      });
    }

    // 4. following, follower 정보 가져오기
    const following = user.following || [];
    const follower = user.follower || [];

    // 5. 성공 응답
    res.status(200).json({
      user: {
        _id: user._id,
        username: user.username,
        accountname: user.accountname,
        image: user.image,
        isfollow: false, // 자기 자신이므로 항상 false
        following: following,
        follower: follower,
        followerCount: follower.length,
        followingCount: following.length,
      },
    });
  } catch (error) {
    console.error("내 정보 조회 오류:", error);
    res.status(500).json({
      message: "서버 오류가 발생했습니다.",
    });
  }
});

/**
 * GET /api/user/checktoken - 토큰 검증 API
 *
 * Headers:
 * {
 *   "Authorization": "Bearer {accessToken}"
 * }
 */
apiRouter.get("/user/checktoken", (req, res) => {
  try {
    // 1. Authorization 헤더에서 토큰 추출
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(200).json({
        isValid: false,
      });
    }

    const token = authHeader.substring(7); // "Bearer " 제거

    // 2. 토큰 검증
    const decoded = verifyToken(token);

    if (!decoded) {
      return res.status(200).json({
        isValid: false,
      });
    }

    // 3. 토큰이 유효한 경우
    res.status(200).json({
      isValid: true,
    });
  } catch (error) {
    console.error("토큰 검증 오류:", error);
    res.status(200).json({
      isValid: false,
    });
  }
});

/**
 * POST /api/user/emailvalid - 이메일 중복 확인 API
 *
 * Request Body:
 * {
 *   "user": {
 *     "email": String (required)
 *   }
 * }
 */
apiRouter.post("/user/emailvalid", (req, res) => {
  try {
    const { user } = req.body;

    // 1. 이메일 입력 확인
    if (!user || !user.email) {
      return res.status(400).json({
        message: "이메일을 입력해주세요.",
      });
    }

    // 2. 이메일 형식 검증
    if (!isValidEmail(user.email)) {
      return res.status(400).json({
        message: "잘못된 이메일 형식입니다.",
      });
    }

    // 3. DB에서 이메일 중복 확인
    const db = router.db;
    const existingEmail = db.get("users").find({ email: user.email }).value();

    // 4. 이메일 중복 여부에 따른 응답
    if (existingEmail) {
      return res.status(200).json({
        ok: false,
        message: "이미 가입된 이메일 주소입니다.",
      });
    }

    // 5. 사용 가능한 이메일
    res.status(200).json({
      ok: true,
      message: "사용 가능한 이메일입니다.",
    });
  } catch (error) {
    console.error("이메일 확인 오류:", error);
    res.status(500).json({
      message: "서버 오류가 발생했습니다.",
    });
  }
});

/**
 * POST /api/user/accountnamevalid - 계정ID 중복 확인 API
 *
 * Request Body:
 * {
 *   "user": {
 *     "accountname": String (required)
 *   }
 * }
 */
apiRouter.post("/user/accountnamevalid", (req, res) => {
  try {
    const { user } = req.body;

    // 1. accountname 입력 확인
    if (!user || !user.accountname) {
      return res.status(400).json({
        message: "계정ID를 입력해주세요.",
      });
    }

    // 2. accountname 형식 검증
    if (!isValidAccountname(user.accountname)) {
      return res.status(400).json({
        message: "영문, 숫자, 밑줄, 마침표만 사용할 수 있습니다.",
      });
    }

    // 3. DB에서 accountname 중복 확인
    const db = router.db;
    const existingAccountname = db
      .get("users")
      .find({ accountname: user.accountname })
      .value();

    // 4. accountname 중복 여부에 따른 응답
    if (existingAccountname) {
      return res.status(200).json({
        ok: false,
        message: "이미 가입된 계정ID입니다.",
      });
    }

    // 5. 사용 가능한 계정ID
    res.status(200).json({
      ok: true,
      message: "사용 가능한 계정ID입니다.",
    });
  } catch (error) {
    console.error("계정ID 확인 오류:", error);
    res.status(500).json({
      message: "서버 오류가 발생했습니다.",
    });
  }
});

/**
 * PUT /api/user - 사용자 정보 수정 API
 *
 * Headers:
 * {
 *   "Authorization": "Bearer {accessToken}"
 * }
 *
 * Request Body:
 * {
 *   "user": {
 *     "username": String,
 *     "accountname": String,
 *     "intro": String,
 *     "image": String
 *   }
 * }
 */
apiRouter.put("/user", (req, res) => {
  try {
    // 1. Authorization 헤더에서 토큰 추출 및 검증
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        message: "인증 토큰이 필요합니다.",
      });
    }

    const token = authHeader.substring(7);
    const decoded = verifyToken(token);

    if (!decoded) {
      return res.status(401).json({
        message: "유효하지 않은 토큰입니다.",
      });
    }

    // 2. Request Body 검증
    const { user } = req.body;

    if (!user) {
      return res.status(400).json({
        message: "잘못된 요청입니다.",
      });
    }

    // 3. DB에서 현재 사용자 정보 조회
    const db = router.db;
    const currentUser = db.get("users").find({ _id: decoded._id }).value();

    if (!currentUser) {
      return res.status(404).json({
        message: "사용자를 찾을 수 없습니다.",
      });
    }

    // 4. accountname이 변경되는 경우 중복 확인
    if (user.accountname && user.accountname !== currentUser.accountname) {
      // accountname 형식 검증
      if (!isValidAccountname(user.accountname)) {
        return res.status(400).json({
          message: "영문, 숫자, 밑줄, 마침표만 사용할 수 있습니다.",
        });
      }

      // 다른 사용자가 이미 사용중인지 확인
      const existingAccountname = db
        .get("users")
        .find({ accountname: user.accountname })
        .value();

      if (existingAccountname) {
        return res.status(400).json({
          message: "이미 사용중인 계정 ID입니다.",
        });
      }
    }

    // 5. 사용자 정보 업데이트
    const updatedUserData = {
      ...currentUser,
      username:
        user.username !== undefined ? user.username : currentUser.username,
      accountname:
        user.accountname !== undefined
          ? user.accountname
          : currentUser.accountname,
      intro: user.intro !== undefined ? user.intro : currentUser.intro,
      image: user.image !== undefined ? user.image : currentUser.image,
    };

    // 6. DB 업데이트
    db.get("users").find({ _id: decoded._id }).assign(updatedUserData).write();

    // 7. following, follower 정보 가져오기
    const following = updatedUserData.following || [];
    const follower = updatedUserData.follower || [];

    // 8. 성공 응답
    res.status(200).json({
      user: {
        _id: updatedUserData._id,
        username: updatedUserData.username,
        accountname: updatedUserData.accountname,
        intro: updatedUserData.intro,
        image: updatedUserData.image,
        following: following,
        follower: follower,
        followerCount: follower.length,
        followingCount: following.length,
      },
    });
  } catch (error) {
    console.error("사용자 정보 수정 오류:", error);
    res.status(500).json({
      message: "서버 오류가 발생했습니다.",
    });
  }
});

/**
 * GET /api/profile/:accountname - 사용자 프로필 조회 API
 *
 * Headers (Optional):
 * {
 *   "Authorization": "Bearer {accessToken}"
 * }
 *
 * URL Parameters:
 * - accountname: 조회할 사용자의 계정ID
 */
apiRouter.get("/profile/:accountname", (req, res) => {
  try {
    const { accountname } = req.params;

    // 1. DB에서 accountname으로 사용자 찾기
    const db = router.db;
    const targetUser = db
      .get("users")
      .find({ accountname: accountname })
      .value();

    // 2. 사용자가 존재하지 않을 때
    if (!targetUser) {
      return res.status(404).json({
        message: "해당 계정이 존재하지 않습니다.",
      });
    }

    // 3. isfollow 확인을 위한 현재 로그인 사용자 확인 (선택적)
    let isfollow = false;
    const authHeader = req.headers.authorization;

    if (authHeader && authHeader.startsWith("Bearer ")) {
      const token = authHeader.substring(7);
      const decoded = verifyToken(token);

      if (decoded) {
        // 현재 로그인한 사용자 정보 조회
        const currentUser = db.get("users").find({ _id: decoded._id }).value();

        if (currentUser && currentUser.following) {
          // 현재 사용자의 following 배열에 targetUser._id가 있는지 확인
          isfollow = currentUser.following.includes(targetUser._id);
        }
      }
    }

    // 4. following, follower 정보 가져오기
    const following = targetUser.following || [];
    const follower = targetUser.follower || [];

    // 5. 성공 응답
    res.status(200).json({
      profile: {
        _id: targetUser._id,
        username: targetUser.username,
        accountname: targetUser.accountname,
        intro: targetUser.intro,
        image: targetUser.image,
        isfollow: isfollow,
        following: following,
        follower: follower,
        followerCount: follower.length,
        followingCount: following.length,
      },
    });
  } catch (error) {
    console.error("프로필 조회 오류:", error);
    res.status(500).json({
      message: "서버 오류가 발생했습니다.",
    });
  }
});

/**
 * POST /api/profile/:accountname/follow - 사용자 팔로우 API
 *
 * Headers:
 * {
 *   "Authorization": "Bearer {accessToken}"
 * }
 *
 * URL Parameters:
 * - accountname: 팔로우할 사용자의 계정ID
 */
apiRouter.post("/profile/:accountname/follow", (req, res) => {
  try {
    // 1. Authorization 헤더에서 토큰 추출 및 검증
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        message: "인증 토큰이 필요합니다.",
      });
    }

    const token = authHeader.substring(7);
    const decoded = verifyToken(token);

    if (!decoded) {
      return res.status(401).json({
        message: "유효하지 않은 토큰입니다.",
      });
    }

    const { accountname } = req.params;

    // 2. DB에서 팔로우 대상 사용자 찾기
    const db = router.db;
    const targetUser = db
      .get("users")
      .find({ accountname: accountname })
      .value();

    // 3. 대상 사용자가 존재하지 않을 때
    if (!targetUser) {
      return res.status(404).json({
        message: "해당 계정이 존재하지 않습니다.",
      });
    }

    // 4. 현재 로그인한 사용자 정보 조회
    const currentUser = db.get("users").find({ _id: decoded._id }).value();

    if (!currentUser) {
      return res.status(404).json({
        message: "사용자를 찾을 수 없습니다.",
      });
    }

    // 5. 자기 자신을 팔로우하려고 할 때
    if (currentUser._id === targetUser._id) {
      return res.status(400).json({
        message: "자기 자신을 팔로우 할 수 없습니다.",
      });
    }

    // 6. following, follower 배열 초기화
    const currentUserFollowing = currentUser.following || [];
    const targetUserFollower = targetUser.follower || [];

    // 7. 이미 팔로우한 경우 중복 방지
    if (currentUserFollowing.includes(targetUser._id)) {
      // 이미 팔로우한 경우에도 성공 응답 반환
      const following = targetUser.following || [];
      const follower = targetUserFollower;

      return res.status(200).json({
        profile: {
          _id: targetUser._id,
          username: targetUser.username,
          accountname: targetUser.accountname,
          intro: targetUser.intro,
          image: targetUser.image,
          isfollow: true,
          following: following,
          follower: follower,
          followerCount: follower.length,
          followingCount: following.length,
        },
      });
    }

    // 8. 팔로우 추가
    currentUserFollowing.push(targetUser._id);
    targetUserFollower.push(currentUser._id);

    // 9. DB 업데이트 - 현재 사용자의 following 업데이트
    db.get("users")
      .find({ _id: currentUser._id })
      .assign({ following: currentUserFollowing })
      .write();

    // 10. DB 업데이트 - 대상 사용자의 follower 업데이트
    db.get("users")
      .find({ _id: targetUser._id })
      .assign({ follower: targetUserFollower })
      .write();

    // 11. 업데이트된 대상 사용자 정보 다시 조회
    const updatedTargetUser = db
      .get("users")
      .find({ _id: targetUser._id })
      .value();
    const following = updatedTargetUser.following || [];
    const follower = updatedTargetUser.follower || [];

    // 12. 성공 응답
    res.status(200).json({
      profile: {
        _id: updatedTargetUser._id,
        username: updatedTargetUser.username,
        accountname: updatedTargetUser.accountname,
        intro: updatedTargetUser.intro,
        image: updatedTargetUser.image,
        isfollow: true,
        following: following,
        follower: follower,
        followerCount: follower.length,
        followingCount: following.length,
      },
    });
  } catch (error) {
    console.error("팔로우 오류:", error);
    res.status(500).json({
      message: "서버 오류가 발생했습니다.",
    });
  }
});

/**
 * DELETE /api/profile/:accountname/unfollow - 사용자 언팔로우 API
 *
 * Headers:
 * {
 *   "Authorization": "Bearer {accessToken}"
 * }
 *
 * URL Parameters:
 * - accountname: 언팔로우할 사용자의 계정ID
 */
apiRouter.delete("/profile/:accountname/unfollow", (req, res) => {
  try {
    // 1. Authorization 헤더에서 토큰 추출 및 검증
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        message: "인증 토큰이 필요합니다.",
      });
    }

    const token = authHeader.substring(7);
    const decoded = verifyToken(token);

    if (!decoded) {
      return res.status(401).json({
        message: "유효하지 않은 토큰입니다.",
      });
    }

    const { accountname } = req.params;

    // 2. DB에서 언팔로우 대상 사용자 찾기
    const db = router.db;
    const targetUser = db
      .get("users")
      .find({ accountname: accountname })
      .value();

    // 3. 대상 사용자가 존재하지 않을 때
    if (!targetUser) {
      return res.status(404).json({
        message: "해당 계정이 존재하지 않습니다.",
      });
    }

    // 4. 현재 로그인한 사용자 정보 조회
    const currentUser = db.get("users").find({ _id: decoded._id }).value();

    if (!currentUser) {
      return res.status(404).json({
        message: "사용자를 찾을 수 없습니다.",
      });
    }

    // 5. following, follower 배열 초기화
    const currentUserFollowing = currentUser.following || [];
    const targetUserFollower = targetUser.follower || [];

    // 6. 언팔로우 처리 - 배열에서 제거
    const updatedCurrentUserFollowing = currentUserFollowing.filter(
      (id) => id !== targetUser._id
    );
    const updatedTargetUserFollower = targetUserFollower.filter(
      (id) => id !== currentUser._id
    );

    // 7. DB 업데이트 - 현재 사용자의 following 업데이트
    db.get("users")
      .find({ _id: currentUser._id })
      .assign({ following: updatedCurrentUserFollowing })
      .write();

    // 8. DB 업데이트 - 대상 사용자의 follower 업데이트
    db.get("users")
      .find({ _id: targetUser._id })
      .assign({ follower: updatedTargetUserFollower })
      .write();

    // 9. 업데이트된 대상 사용자 정보 다시 조회
    const updatedTargetUser = db
      .get("users")
      .find({ _id: targetUser._id })
      .value();
    const following = updatedTargetUser.following || [];
    const follower = updatedTargetUser.follower || [];

    // 10. 성공 응답
    res.status(200).json({
      profile: {
        _id: updatedTargetUser._id,
        username: updatedTargetUser.username,
        accountname: updatedTargetUser.accountname,
        intro: updatedTargetUser.intro,
        image: updatedTargetUser.image,
        isfollow: false,
        following: following,
        follower: follower,
        followerCount: follower.length,
        followingCount: following.length,
      },
    });
  } catch (error) {
    console.error("언팔로우 오류:", error);
    res.status(500).json({
      message: "서버 오류가 발생했습니다.",
    });
  }
});

/**
 * GET /api/profile/:accountname/following - 팔로잉 목록 조회 API
 *
 * Headers (Optional):
 * {
 *   "Authorization": "Bearer {accessToken}"
 * }
 *
 * URL Parameters:
 * - accountname: 조회할 사용자의 계정ID
 *
 * Query Parameters:
 * - limit: 조회할 개수 (기본값: 10)
 * - skip: 건너뛸 개수 (기본값: 0)
 */
apiRouter.get("/profile/:accountname/following", (req, res) => {
  try {
    const { accountname } = req.params;
    const limit = parseInt(req.query.limit) || 10;
    const skip = parseInt(req.query.skip) || 0;

    // 1. DB에서 accountname으로 사용자 찾기
    const db = router.db;
    const targetUser = db
      .get("users")
      .find({ accountname: accountname })
      .value();

    // 2. 사용자가 존재하지 않을 때
    if (!targetUser) {
      return res.status(404).json({
        message: "해당 계정이 존재하지 않습니다.",
      });
    }

    // 3. following 목록 가져오기
    const followingIds = targetUser.following || [];

    // 4. following이 없으면 빈 배열 반환
    if (followingIds.length === 0) {
      return res.status(200).json([]);
    }

    // 5. 현재 로그인한 사용자 확인 (선택적)
    let currentUser = null;
    const authHeader = req.headers.authorization;

    if (authHeader && authHeader.startsWith("Bearer ")) {
      const token = authHeader.substring(7);
      const decoded = verifyToken(token);

      if (decoded) {
        currentUser = db.get("users").find({ _id: decoded._id }).value();
      }
    }

    const currentUserFollowing = currentUser?.following || [];

    // 6. 페이지네이션 적용하여 following ID 슬라이스
    const paginatedFollowingIds = followingIds.slice(skip, skip + limit);

    // 7. 각 following ID에 해당하는 사용자 정보 조회
    const followingList = paginatedFollowingIds
      .map((followingId) => {
        const user = db.get("users").find({ _id: followingId }).value();

        if (!user) return null;

        // isfollow 확인
        const isfollow = currentUserFollowing.includes(user._id);
        const following = user.following || [];
        const follower = user.follower || [];

        return {
          _id: user._id,
          username: user.username,
          accountname: user.accountname,
          intro: user.intro,
          image: user.image,
          isfollow: isfollow,
          following: following,
          follower: follower,
          followerCount: follower.length,
          followingCount: following.length,
        };
      })
      .filter((user) => user !== null); // null 제거 (존재하지 않는 사용자)

    // 8. 성공 응답
    res.status(200).json({ following: followingList });
  } catch (error) {
    console.error("팔로잉 목록 조회 오류:", error);
    res.status(500).json({
      message: "서버 오류가 발생했습니다.",
    });
  }
});

/**
 * GET /api/profile/:accountname/follower - 팔로워 목록 조회 API
 *
 * Headers (Optional):
 * {
 *   "Authorization": "Bearer {accessToken}"
 * }
 *
 * URL Parameters:
 * - accountname: 조회할 사용자의 계정ID
 *
 * Query Parameters:
 * - limit: 조회할 개수 (기본값: 10)
 * - skip: 건너뛸 개수 (기본값: 0)
 */
apiRouter.get("/profile/:accountname/follower", (req, res) => {
  try {
    const { accountname } = req.params;
    const limit = parseInt(req.query.limit) || 10;
    const skip = parseInt(req.query.skip) || 0;

    // 1. DB에서 accountname으로 사용자 찾기
    const db = router.db;
    const targetUser = db
      .get("users")
      .find({ accountname: accountname })
      .value();

    // 2. 사용자가 존재하지 않을 때
    if (!targetUser) {
      return res.status(404).json({
        message: "해당 계정이 존재하지 않습니다.",
      });
    }

    // 3. follower 목록 가져오기
    const followerIds = targetUser.follower || [];

    // 4. follower가 없으면 빈 배열 반환
    if (followerIds.length === 0) {
      return res.status(200).json([]);
    }

    // 5. 현재 로그인한 사용자 확인 (선택적)
    let currentUser = null;
    const authHeader = req.headers.authorization;

    if (authHeader && authHeader.startsWith("Bearer ")) {
      const token = authHeader.substring(7);
      const decoded = verifyToken(token);

      if (decoded) {
        currentUser = db.get("users").find({ _id: decoded._id }).value();
      }
    }

    const currentUserFollowing = currentUser?.following || [];

    // 6. 페이지네이션 적용하여 follower ID 슬라이스
    const paginatedFollowerIds = followerIds.slice(skip, skip + limit);
    console.log("followerIds", followerIds);
    // 7. 각 follower ID에 해당하는 사용자 정보 조회
    const followerList = paginatedFollowerIds
      .map((followerId) => {
        const user = db.get("users").find({ _id: followerId }).value();

        if (!user) return null;

        // isfollow 확인
        const isfollow = currentUserFollowing.includes(user._id);
        const following = user.following || [];
        const follower = user.follower || [];

        return {
          _id: user._id,
          username: user.username,
          accountname: user.accountname,
          intro: user.intro,
          image: user.image,
          isfollow: isfollow,
          following: following,
          follower: follower,
          followerCount: follower.length,
          followingCount: following.length,
        };
      })
      .filter((user) => user !== null); // null 제거 (존재하지 않는 사용자)

    // 8. 성공 응답
    res.status(200).json({ follower: followerList });
  } catch (error) {
    console.error("팔로워 목록 조회 오류:", error);
    res.status(500).json({
      message: "서버 오류가 발생했습니다.",
    });
  }
});

/**
 * GET /api/user/searchuser - 사용자 검색 API
 *
 * Query Parameters:
 * - keyword: 검색 키워드 (username 또는 accountname에서 검색)
 */
apiRouter.get("/user/searchuser", (req, res) => {
  try {
    const { keyword } = req.query;

    // 1. 키워드가 없으면 빈 배열 반환
    if (!keyword || keyword.trim() === "") {
      return res.status(200).json([]);
    }

    // 2. DB에서 모든 사용자 조회
    const db = router.db;
    const allUsers = db.get("users").value();

    // 3. keyword로 필터링 (username 또는 accountname에 포함된 경우)
    const searchKeyword = keyword.toLowerCase();
    const filteredUsers = allUsers.filter((user) => {
      const username = (user.username || "").toLowerCase();
      const accountname = (user.accountname || "").toLowerCase();

      return (
        username.includes(searchKeyword) || accountname.includes(searchKeyword)
      );
    });

    // 4. 결과 매핑 (필요한 필드만 반환)
    const searchResults = filteredUsers.map((user) => {
      const following = user.following || [];
      const follower = user.follower || [];

      return {
        _id: user._id,
        username: user.username,
        accountname: user.accountname,
        following: following,
        follower: follower,
        followerCount: follower.length,
        followingCount: following.length,
      };
    });

    // 5. 성공 응답
    res.status(200).json(searchResults);
  } catch (error) {
    console.error("사용자 검색 오류:", error);
    res.status(500).json({
      message: "서버 오류가 발생했습니다.",
    });
  }
});

/**
 * POST /api/post - 게시글 작성 API
 *
 * Headers:
 * {
 *   "Authorization": "Bearer {accessToken}"
 * }
 *
 * Request Body:
 * {
 *   "post": {
 *     "content": String,
 *     "image": String (imageurl1, imageurl2 형식)
 *   }
 * }
 */
apiRouter.post("/post", (req, res) => {
  try {
    // 1. Authorization 헤더에서 토큰 추출 및 검증
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        message: "인증 토큰이 필요합니다.",
      });
    }

    const token = authHeader.substring(7);
    const decoded = verifyToken(token);

    if (!decoded) {
      return res.status(401).json({
        message: "유효하지 않은 토큰입니다.",
      });
    }

    // 2. Request Body 검증
    const { post } = req.body;

    if (!post) {
      return res.status(400).json({
        message: "잘못된 요청입니다.",
      });
    }

    // 3. content 또는 image 중 하나는 필수
    if (
      (!post.content || post.content.trim() === "") &&
      (!post.image || post.image.trim() === "")
    ) {
      return res.status(400).json({
        message: "내용 또는 이미지를 입력해주세요.",
      });
    }

    // 4. DB에서 작성자 정보 조회
    const db = router.db;
    const author = db.get("users").find({ _id: decoded._id }).value();

    if (!author) {
      return res.status(404).json({
        message: "사용자를 찾을 수 없습니다.",
      });
    }

    // 5. 새 게시글 생성
    const now = new Date().toISOString();
    const newPost = {
      id: generateId(),
      content: post.content || "",
      image: post.image || "",
      createdAt: now,
      updatedAt: now,
      hearted: false,
      heartCount: 0,
      commentCount: 0,
      authorId: author._id, // 작성자 ID 저장
    };

    // 6. DB에 게시글 추가
    db.get("posts").push(newPost).write();

    // 7. author 정보 구성
    const authorFollowing = author.following || [];
    const authorFollower = author.follower || [];

    const authorInfo = {
      _id: author._id,
      username: author.username,
      accountname: author.accountname,
      intro: author.intro || "",
      image: author.image || "",
      isfollow: false, // 자기 자신의 게시글이므로 false
      following: authorFollowing,
      follower: authorFollower,
      followerCount: authorFollower.length,
      followingCount: authorFollowing.length,
    };

    // 8. 응답용 게시글 객체 생성
    const responsePost = {
      id: newPost.id,
      content: newPost.content,
      image: newPost.image,
      createdAt: newPost.createdAt,
      updatedAt: newPost.updatedAt,
      hearted: newPost.hearted,
      heartCount: newPost.heartCount,
      commentCount: newPost.commentCount,
      author: authorInfo,
    };

    // 9. 성공 응답
    res.status(201).json({
      post: responsePost,
    });
  } catch (error) {
    console.error("게시글 작성 오류:", error);
    res.status(500).json({
      message: "서버 오류가 발생했습니다.",
    });
  }
});

/**
 * GET /api/post/feed - 팔로잉 게시글 목록 조회 API
 *
 * Headers:
 * {
 *   "Authorization": "Bearer {accessToken}"
 * }
 *
 * Query Parameters:
 * - limit: 조회할 개수 (기본값: 10)
 * - skip: 건너뛸 개수 (기본값: 0)
 */
apiRouter.get("/post/feed", (req, res) => {
  try {
    // 1. Authorization 헤더에서 토큰 추출 및 검증
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        message: "인증 토큰이 필요합니다.",
      });
    }

    const token = authHeader.substring(7);
    const decoded = verifyToken(token);

    if (!decoded) {
      return res.status(401).json({
        message: "유효하지 않은 토큰입니다.",
      });
    }

    const limit = parseInt(req.query.limit) || 10;
    const skip = parseInt(req.query.skip) || 0;

    // 2. DB에서 현재 사용자 정보 조회
    const db = router.db;
    const currentUser = db.get("users").find({ _id: decoded._id }).value();

    if (!currentUser) {
      return res.status(404).json({
        message: "사용자를 찾을 수 없습니다.",
      });
    }

    // 3. 현재 사용자의 following 목록 가져오기
    const followingIds = currentUser.following || [];

    // 4. following이 없으면 빈 배열 반환
    if (followingIds.length === 0) {
      return res.status(200).json({
        posts: [],
      });
    }

    // 5. 모든 게시글 가져오기
    const allPosts = db.get("posts").value();

    // 6. 팔로잉한 사용자의 게시글만 필터링
    const followingPosts = allPosts.filter((post) =>
      followingIds.includes(post.authorId)
    );

    // 7. createdAt 기준으로 최신순 정렬
    const sortedPosts = followingPosts.sort((a, b) => {
      return new Date(b.createdAt) - new Date(a.createdAt);
    });

    // 8. 페이지네이션 적용
    const paginatedPosts = sortedPosts.slice(skip, skip + limit);

    // 9. 각 게시글에 author 정보 추가
    const postsWithAuthor = paginatedPosts
      .map((post) => {
        const author = db.get("users").find({ _id: post.authorId }).value();

        if (!author) {
          return null;
        }

        const authorFollowing = author.following || [];
        const authorFollower = author.follower || [];

        return {
          id: post.id,
          content: post.content,
          image: post.image,
          createdAt: post.createdAt,
          updatedAt: post.updatedAt,
          hearted: post.hearted,
          heartCount: post.heartCount,
          commentCount: post.commentCount,
          author: {
            _id: author._id,
            username: author.username,
            accountname: author.accountname,
            intro: author.intro || "",
            image: author.image || "",
            isfollow: true, // 팔로잉한 사용자의 게시글이므로 항상 true
            following: authorFollowing,
            follower: authorFollower,
            followerCount: authorFollower.length,
            followingCount: authorFollowing.length,
          },
        };
      })
      .filter((post) => post !== null); // null 제거

    // 10. 성공 응답
    res.status(200).json({
      posts: postsWithAuthor,
    });
  } catch (error) {
    console.error("팔로잉 게시글 목록 조회 오류:", error);
    res.status(500).json({
      message: "서버 오류가 발생했습니다.",
    });
  }
});

/**
 * GET /api/post/:accountname/userpost - 유저별 게시글 목록 조회 API
 *
 * Headers (Optional):
 * {
 *   "Authorization": "Bearer {accessToken}"
 * }
 *
 * URL Parameters:
 * - accountname: 조회할 사용자의 계정ID
 *
 * Query Parameters:
 * - limit: 조회할 개수 (기본값: 10)
 * - skip: 건너뛸 개수 (기본값: 0)
 */
apiRouter.get("/post/:accountname/userpost", (req, res) => {
  try {
    const { accountname } = req.params;
    const limit = parseInt(req.query.limit) || 10;
    const skip = parseInt(req.query.skip) || 0;

    // 1. DB에서 accountname으로 사용자 찾기
    const db = router.db;
    const targetUser = db
      .get("users")
      .find({ accountname: accountname })
      .value();

    // 2. 사용자가 존재하지 않을 때
    if (!targetUser) {
      return res.status(404).json({
        message: "해당 계정이 존재하지 않습니다.",
      });
    }

    // 3. 현재 로그인한 사용자 확인 (선택적)
    let currentUser = null;
    const authHeader = req.headers.authorization;

    if (authHeader && authHeader.startsWith("Bearer ")) {
      const token = authHeader.substring(7);
      const decoded = verifyToken(token);

      if (decoded) {
        currentUser = db.get("users").find({ _id: decoded._id }).value();
      }
    }

    const currentUserFollowing = currentUser?.following || [];

    // 4. 모든 게시글 가져오기
    const allPosts = db.get("posts").value();

    // 5. 해당 사용자의 게시글만 필터링
    const userPosts = allPosts.filter(
      (post) => post.authorId === targetUser._id
    );

    // 6. createdAt 기준으로 최신순 정렬
    const sortedPosts = userPosts.sort((a, b) => {
      return new Date(b.createdAt) - new Date(a.createdAt);
    });

    // 7. 페이지네이션 적용
    const paginatedPosts = sortedPosts.slice(skip, skip + limit);

    // 8. 각 게시글에 author 정보 추가
    const authorFollowing = targetUser.following || [];
    const authorFollower = targetUser.follower || [];
    const isfollow = currentUserFollowing.includes(targetUser._id);

    const postsWithAuthor = paginatedPosts.map((post) => {
      return {
        id: post.id,
        content: post.content,
        image: post.image,
        createdAt: post.createdAt,
        updatedAt: post.updatedAt,
        hearted: post.hearted,
        heartCount: post.heartCount,
        commentCount: post.commentCount,
        author: {
          _id: targetUser._id,
          username: targetUser.username,
          accountname: targetUser.accountname,
          intro: targetUser.intro || "",
          image: targetUser.image || "",
          isfollow: isfollow,
          following: authorFollowing,
          follower: authorFollower,
          followerCount: authorFollower.length,
          followingCount: authorFollowing.length,
        },
      };
    });

    // 9. 성공 응답
    res.status(200).json({
      post: postsWithAuthor,
    });
  } catch (error) {
    console.error("유저별 게시글 목록 조회 오류:", error);
    res.status(500).json({
      message: "서버 오류가 발생했습니다.",
    });
  }
});

/**
 * GET /api/post/:post_id - 게시글 상세 조회 API
 *
 * Headers (Optional):
 * {
 *   "Authorization": "Bearer {accessToken}"
 * }
 *
 * URL Parameters:
 * - post_id: 조회할 게시글 ID
 */
apiRouter.get("/post/:post_id", (req, res) => {
  try {
    const { post_id } = req.params;

    // 1. DB에서 게시글 조회
    const db = router.db;
    const post = db.get("posts").find({ id: post_id }).value();

    // 2. 게시글이 존재하지 않을 때
    if (!post) {
      return res.status(404).json({
        message: "존재하지 않는 게시글입니다.",
      });
    }

    // 3. 작성자 정보 조회
    const author = db.get("users").find({ _id: post.authorId }).value();

    if (!author) {
      return res.status(404).json({
        message: "작성자를 찾을 수 없습니다.",
      });
    }

    // 4. 현재 로그인한 사용자 확인 (선택적)
    let currentUser = null;
    const authHeader = req.headers.authorization;

    if (authHeader && authHeader.startsWith("Bearer ")) {
      const token = authHeader.substring(7);
      const decoded = verifyToken(token);

      if (decoded) {
        currentUser = db.get("users").find({ _id: decoded._id }).value();
      }
    }

    const currentUserFollowing = currentUser?.following || [];

    // 5. author 정보 구성
    const authorFollowing = author.following || [];
    const authorFollower = author.follower || [];
    const isfollow = currentUserFollowing.includes(author._id);

    const postDetail = {
      id: post.id,
      content: post.content,
      image: post.image,
      createdAt: post.createdAt,
      updatedAt: post.updatedAt,
      hearted: post.hearted,
      heartCount: post.heartCount,
      commentCount: post.commentCount,
      author: {
        _id: author._id,
        username: author.username,
        accountname: author.accountname,
        intro: author.intro || "",
        image: author.image || "",
        isfollow: isfollow,
        following: authorFollowing,
        follower: authorFollower,
        followerCount: authorFollower.length,
        followingCount: authorFollowing.length,
      },
    };

    // 6. 성공 응답
    res.status(200).json({
      post: postDetail,
    });
  } catch (error) {
    console.error("게시글 상세 조회 오류:", error);
    res.status(500).json({
      message: "서버 오류가 발생했습니다.",
    });
  }
});

/**
 * PUT /api/post/:post_id - 게시글 수정 API
 *
 * Headers:
 * {
 *   "Authorization": "Bearer {accessToken}"
 * }
 *
 * URL Parameters:
 * - post_id: 수정할 게시글 ID
 *
 * Request Body:
 * {
 *   "post": {
 *     "content": String,
 *     "image": String
 *   }
 * }
 */
apiRouter.put("/post/:post_id", (req, res) => {
  try {
    // 1. Authorization 헤더에서 토큰 추출 및 검증
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        message: "인증 토큰이 필요합니다.",
      });
    }

    const token = authHeader.substring(7);
    const decoded = verifyToken(token);

    if (!decoded) {
      return res.status(401).json({
        message: "유효하지 않은 토큰입니다.",
      });
    }

    const { post_id } = req.params;
    const { post } = req.body;

    // 2. Request Body 검증
    if (!post) {
      return res.status(400).json({
        message: "잘못된 요청입니다.",
      });
    }

    // 3. DB에서 게시글 조회
    const db = router.db;
    const existingPost = db.get("posts").find({ id: post_id }).value();

    // 4. 게시글이 존재하지 않을 때
    if (!existingPost) {
      return res.status(404).json({
        message: "존재하지 않는 게시글입니다.",
      });
    }

    // 5. 작성자 본인 확인
    if (existingPost.authorId !== decoded._id) {
      return res.status(403).json({
        message: "잘못된 요청입니다. 로그인 정보를 확인하세요.",
      });
    }

    // 6. 게시글 업데이트
    const updatedData = {
      content: post.content !== undefined ? post.content : existingPost.content,
      image: post.image !== undefined ? post.image : existingPost.image,
      updatedAt: new Date().toISOString(),
    };

    db.get("posts").find({ id: post_id }).assign(updatedData).write();

    // 7. 업데이트된 게시글 다시 조회
    const updatedPost = db.get("posts").find({ id: post_id }).value();

    // 8. 작성자 정보 조회
    const author = db.get("users").find({ _id: updatedPost.authorId }).value();

    if (!author) {
      return res.status(404).json({
        message: "작성자를 찾을 수 없습니다.",
      });
    }

    // 9. author 정보 구성
    const authorFollowing = author.following || [];
    const authorFollower = author.follower || [];

    const postDetail = {
      id: updatedPost.id,
      content: updatedPost.content,
      image: updatedPost.image,
      createdAt: updatedPost.createdAt,
      updatedAt: updatedPost.updatedAt,
      hearted: updatedPost.hearted,
      heartCount: updatedPost.heartCount,
      commentCount: updatedPost.commentCount,
      author: {
        _id: author._id,
        username: author.username,
        accountname: author.accountname,
        intro: author.intro || "",
        image: author.image || "",
        isfollow: false, // 자기 자신의 게시글이므로 false
        following: authorFollowing,
        follower: authorFollower,
        followerCount: authorFollower.length,
        followingCount: authorFollowing.length,
      },
    };

    // 10. 성공 응답
    res.status(200).json({
      post: postDetail,
    });
  } catch (error) {
    console.error("게시글 수정 오류:", error);
    res.status(500).json({
      message: "서버 오류가 발생했습니다.",
    });
  }
});

/**
 * DELETE /api/post/:post_id - 게시글 삭제 API
 *
 * Headers:
 * {
 *   "Authorization": "Bearer {accessToken}"
 * }
 *
 * URL Parameters:
 * - post_id: 삭제할 게시글 ID
 */
apiRouter.delete("/post/:post_id", (req, res) => {
  try {
    // 1. Authorization 헤더에서 토큰 추출 및 검증
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        message: "인증 토큰이 필요합니다.",
      });
    }

    const token = authHeader.substring(7);
    const decoded = verifyToken(token);

    if (!decoded) {
      return res.status(401).json({
        message: "유효하지 않은 토큰입니다.",
      });
    }

    const { post_id } = req.params;

    // 2. DB에서 게시글 조회
    const db = router.db;
    const existingPost = db.get("posts").find({ id: post_id }).value();

    // 3. 게시글이 존재하지 않을 때
    if (!existingPost) {
      return res.status(404).json({
        message: "존재하지 않는 게시글입니다.",
      });
    }

    // 4. 작성자 본인 확인
    if (existingPost.authorId !== decoded._id) {
      return res.status(403).json({
        message: "게시글 작성자만 게시글을 삭제할 수 있습니다.",
      });
    }

    // 5. 게시글 삭제
    db.get("posts").remove({ id: post_id }).write();

    // 6. 성공 응답
    res.status(200).json({
      message: "삭제되었습니다.",
    });
  } catch (error) {
    console.error("게시글 삭제 오류:", error);
    res.status(500).json({
      message: "서버 오류가 발생했습니다.",
    });
  }
});

/**
 * POST /api/post/:post_id/report - 게시글 신고 API
 *
 * Headers:
 * {
 *   "Authorization": "Bearer {accessToken}"
 * }
 *
 * URL Parameters:
 * - post_id: 신고할 게시글 ID
 */
apiRouter.post("/post/:post_id/report", (req, res) => {
  try {
    // 1. Authorization 헤더에서 토큰 추출 및 검증
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        message: "인증 토큰이 필요합니다.",
      });
    }

    const token = authHeader.substring(7);
    const decoded = verifyToken(token);

    if (!decoded) {
      return res.status(401).json({
        message: "유효하지 않은 토큰입니다.",
      });
    }

    const { post_id } = req.params;

    // 2. DB에서 게시글 조회
    const db = router.db;
    const post = db.get("posts").find({ id: post_id }).value();

    // 3. 게시글이 존재하지 않을 때
    if (!post) {
      return res.status(404).json({
        message: "존재하지 않는 게시글입니다.",
      });
    }

    // 4. 신고 정보 생성
    const newReport = {
      id: generateId(),
      postId: post_id,
      reporterId: decoded._id,
      createdAt: new Date().toISOString(),
    };

    // 5. DB에 신고 추가
    db.get("reports").push(newReport).write();

    // 6. 성공 응답
    res.status(200).json({
      report: {
        post: post_id,
      },
    });
  } catch (error) {
    console.error("게시글 신고 오류:", error);
    res.status(500).json({
      message: "서버 오류가 발생했습니다.",
    });
  }
});

/**
 * GET /api/post - 게시글 전체보기 API
 *
 * Headers (Optional):
 * {
 *   "Authorization": "Bearer {accessToken}"
 * }
 *
 * Query Parameters:
 * - limit: 조회할 개수 (기본값: 10)
 * - skip: 건너뛸 개수 (기본값: 0)
 */
apiRouter.get("/post", (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 10;
    const skip = parseInt(req.query.skip) || 0;

    // 1. 현재 로그인한 사용자 확인 (선택적)
    const db = router.db;
    let currentUser = null;
    const authHeader = req.headers.authorization;

    if (authHeader && authHeader.startsWith("Bearer ")) {
      const token = authHeader.substring(7);
      const decoded = verifyToken(token);

      if (decoded) {
        currentUser = db.get("users").find({ _id: decoded._id }).value();
      }
    }

    const currentUserFollowing = currentUser?.following || [];

    // 2. 모든 게시글 가져오기
    const allPosts = db.get("posts").value();

    // 3. createdAt 기준으로 최신순 정렬
    const sortedPosts = allPosts.sort((a, b) => {
      return new Date(b.createdAt) - new Date(a.createdAt);
    });

    // 4. 페이지네이션 적용
    const paginatedPosts = sortedPosts.slice(skip, skip + limit);

    // 5. 각 게시글에 author 정보 추가
    const postsWithAuthor = paginatedPosts
      .map((post) => {
        const author = db.get("users").find({ _id: post.authorId }).value();

        if (!author) {
          return null;
        }

        const authorFollowing = author.following || [];
        const authorFollower = author.follower || [];
        const isfollow = currentUserFollowing.includes(author._id);

        return {
          id: post.id,
          content: post.content,
          image: post.image,
          createdAt: post.createdAt,
          updatedAt: post.updatedAt,
          hearted: post.hearted,
          heartCount: post.heartCount,
          commentCount: post.commentCount,
          author: {
            _id: author._id,
            username: author.username,
            accountname: author.accountname,
            intro: author.intro || "",
            image: author.image || "",
            isfollow: isfollow,
            following: authorFollowing,
            follower: authorFollower,
            followerCount: authorFollower.length,
            followingCount: authorFollowing.length,
          },
        };
      })
      .filter((post) => post !== null); // null 제거

    // 6. 성공 응답
    res.status(200).json({
      posts: postsWithAuthor,
    });
  } catch (error) {
    console.error("게시글 전체보기 오류:", error);
    res.status(500).json({
      message: "서버 오류가 발생했습니다.",
    });
  }
});

/**
 * POST /api/post/:post_id/heart - 게시글 좋아요 API
 *
 * Headers:
 * {
 *   "Authorization": "Bearer {accessToken}"
 * }
 *
 * URL Parameters:
 * - post_id: 좋아요할 게시글 ID
 */
apiRouter.post("/post/:post_id/heart", (req, res) => {
  try {
    // 1. Authorization 헤더에서 토큰 추출 및 검증
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        message: "인증 토큰이 필요합니다.",
      });
    }

    const token = authHeader.substring(7);
    const decoded = verifyToken(token);

    if (!decoded) {
      return res.status(401).json({
        message: "유효하지 않은 토큰입니다.",
      });
    }

    const { post_id } = req.params;

    // 2. DB에서 게시글 조회
    const db = router.db;
    const post = db.get("posts").find({ id: post_id }).value();

    // 3. 게시글이 존재하지 않을 때
    if (!post) {
      return res.status(404).json({
        message: "존재하지 않는 게시글입니다.",
      });
    }

    // 4. 현재 사용자 정보 조회
    const currentUser = db.get("users").find({ _id: decoded._id }).value();

    if (!currentUser) {
      return res.status(404).json({
        message: "사용자를 찾을 수 없습니다.",
      });
    }

    // 5. 이미 좋아요한 게시글인지 확인
    const existingHeart = db
      .get("hearts")
      .find({ postId: post_id, userId: decoded._id })
      .value();

    let hearted = false;
    let heartCount = post.heartCount || 0;

    if (existingHeart) {
      // 이미 좋아요한 경우 - 좋아요 취소
      db.get("hearts").remove({ postId: post_id, userId: decoded._id }).write();

      heartCount = Math.max(0, heartCount - 1);
      hearted = false;
    } else {
      // 좋아요 추가
      const newHeart = {
        id: generateId(),
        postId: post_id,
        userId: decoded._id,
        createdAt: new Date().toISOString(),
      };

      db.get("hearts").push(newHeart).write();

      heartCount = heartCount + 1;
      hearted = true;
    }

    // 6. 게시글의 heartCount 업데이트
    db.get("posts")
      .find({ id: post_id })
      .assign({ heartCount: heartCount, hearted: hearted })
      .write();

    // 7. 업데이트된 게시글 조회
    const updatedPost = db.get("posts").find({ id: post_id }).value();

    // 8. 작성자 정보 조회
    const author = db.get("users").find({ _id: updatedPost.authorId }).value();

    if (!author) {
      return res.status(404).json({
        message: "작성자를 찾을 수 없습니다.",
      });
    }

    // 9. author 정보 구성
    const currentUserFollowing = currentUser.following || [];
    const authorFollowing = author.following || [];
    const authorFollower = author.follower || [];
    const isfollow = currentUserFollowing.includes(author._id);

    const postDetail = {
      id: updatedPost.id,
      content: updatedPost.content,
      image: updatedPost.image,
      createdAt: updatedPost.createdAt,
      updatedAt: updatedPost.updatedAt,
      hearted: hearted,
      heartCount: heartCount,
      commentCount: updatedPost.commentCount,
      author: {
        _id: author._id,
        username: author.username,
        accountname: author.accountname,
        intro: author.intro || "",
        image: author.image || "",
        isfollow: isfollow,
        following: authorFollowing,
        follower: authorFollower,
        followerCount: authorFollower.length,
        followingCount: authorFollowing.length,
      },
    };

    // 10. 성공 응답
    res.status(200).json({
      post: postDetail,
    });
  } catch (error) {
    console.error("게시글 좋아요 오류:", error);
    res.status(500).json({
      message: "서버 오류가 발생했습니다.",
    });
  }
});

/**
 * DELETE /api/post/:post_id/unheart - 게시글 좋아요 취소 API
 *
 * Headers:
 * {
 *   "Authorization": "Bearer {accessToken}"
 * }
 *
 * URL Parameters:
 * - post_id: 좋아요 취소할 게시글 ID
 */
apiRouter.delete("/post/:post_id/unheart", (req, res) => {
  try {
    // 1. Authorization 헤더에서 토큰 추출 및 검증
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        message: "인증 토큰이 필요합니다.",
      });
    }

    const token = authHeader.substring(7);
    const decoded = verifyToken(token);

    if (!decoded) {
      return res.status(401).json({
        message: "유효하지 않은 토큰입니다.",
      });
    }

    const { post_id } = req.params;

    // 2. DB에서 게시글 조회
    const db = router.db;
    const post = db.get("posts").find({ id: post_id }).value();

    // 3. 게시글이 존재하지 않을 때
    if (!post) {
      return res.status(404).json({
        message: "존재하지 않는 게시글입니다.",
      });
    }

    // 4. 현재 사용자 정보 조회
    const currentUser = db.get("users").find({ _id: decoded._id }).value();

    if (!currentUser) {
      return res.status(404).json({
        message: "사용자를 찾을 수 없습니다.",
      });
    }

    // 5. 좋아요 확인 및 제거
    const existingHeart = db
      .get("hearts")
      .find({ postId: post_id, userId: decoded._id })
      .value();

    let heartCount = post.heartCount || 0;

    if (existingHeart) {
      // 좋아요 제거
      db.get("hearts").remove({ postId: post_id, userId: decoded._id }).write();

      heartCount = Math.max(0, heartCount - 1);
    }

    // 6. 게시글의 heartCount 업데이트
    db.get("posts")
      .find({ id: post_id })
      .assign({ heartCount: heartCount, hearted: false })
      .write();

    // 7. 업데이트된 게시글 조회
    const updatedPost = db.get("posts").find({ id: post_id }).value();

    // 8. 작성자 정보 조회
    const author = db.get("users").find({ _id: updatedPost.authorId }).value();

    if (!author) {
      return res.status(404).json({
        message: "작성자를 찾을 수 없습니다.",
      });
    }

    // 9. author 정보 구성
    const currentUserFollowing = currentUser.following || [];
    const authorFollowing = author.following || [];
    const authorFollower = author.follower || [];
    const isfollow = currentUserFollowing.includes(author._id);

    const postDetail = {
      id: updatedPost.id,
      content: updatedPost.content,
      image: updatedPost.image,
      createdAt: updatedPost.createdAt,
      updatedAt: updatedPost.updatedAt,
      hearted: false,
      heartCount: heartCount,
      commentCount: updatedPost.commentCount,
      author: {
        _id: author._id,
        username: author.username,
        accountname: author.accountname,
        intro: author.intro || "",
        image: author.image || "",
        isfollow: isfollow,
        following: authorFollowing,
        follower: authorFollower,
        followerCount: authorFollower.length,
        followingCount: authorFollowing.length,
      },
    };

    // 10. 성공 응답
    res.status(200).json({
      post: postDetail,
    });
  } catch (error) {
    console.error("게시글 좋아요 취소 오류:", error);
    res.status(500).json({
      message: "서버 오류가 발생했습니다.",
    });
  }
});

/**
 * POST /api/post/:post_id/comments - 댓글 작성 API
 *
 * Headers:
 * {
 *   "Authorization": "Bearer {accessToken}"
 * }
 *
 * URL Parameters:
 * - post_id: 댓글을 작성할 게시글 ID
 *
 * Request Body:
 * {
 *   "comment": {
 *     "content": String
 *   }
 * }
 */
apiRouter.post("/post/:post_id/comments", (req, res) => {
  try {
    // 1. Authorization 헤더에서 토큰 추출 및 검증
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        message: "인증 토큰이 필요합니다.",
      });
    }

    const token = authHeader.substring(7);
    const decoded = verifyToken(token);

    if (!decoded) {
      return res.status(401).json({
        message: "유효하지 않은 토큰입니다.",
      });
    }

    const { post_id } = req.params;
    const { comment } = req.body;

    // 2. Request Body 검증
    if (!comment || !comment.content || comment.content.trim() === "") {
      return res.status(400).json({
        message: "댓글을 입력해주세요.",
      });
    }

    // 3. DB에서 게시글 조회
    const db = router.db;
    const post = db.get("posts").find({ id: post_id }).value();

    // 4. 게시글이 존재하지 않을 때
    if (!post) {
      return res.status(404).json({
        message: "존재하지 않는 게시글입니다.",
      });
    }

    // 5. 댓글 작성자 정보 조회
    const author = db.get("users").find({ _id: decoded._id }).value();

    if (!author) {
      return res.status(404).json({
        message: "사용자를 찾을 수 없습니다.",
      });
    }

    // 6. 새 댓글 생성
    const newComment = {
      id: generateId(),
      content: comment.content,
      createdAt: new Date().toISOString(),
      postId: post_id,
      authorId: author._id,
    };

    // 7. DB에 댓글 추가
    db.get("comments").push(newComment).write();

    // 8. 게시글의 commentCount 증가
    const currentCommentCount = post.commentCount || 0;
    db.get("posts")
      .find({ id: post_id })
      .assign({ commentCount: currentCommentCount + 1 })
      .write();

    // 9. author 정보 구성
    const authorFollowing = author.following || [];
    const authorFollower = author.follower || [];

    const commentResponse = {
      id: newComment.id,
      content: newComment.content,
      createdAt: newComment.createdAt,
      author: {
        _id: author._id,
        username: author.username,
        accountname: author.accountname,
        intro: author.intro || "",
        image: author.image || "",
        isfollow: false, // 자기 자신의 댓글이므로 false
        following: authorFollowing,
        follower: authorFollower,
        followerCount: authorFollower.length,
        followingCount: authorFollowing.length,
      },
    };

    // 10. 성공 응답
    res.status(201).json({
      comment: commentResponse,
    });
  } catch (error) {
    console.error("댓글 작성 오류:", error);
    res.status(500).json({
      message: "서버 오류가 발생했습니다.",
    });
  }
});

/**
 * GET /api/post/:post_id/comments - 댓글 리스트 조회 API
 *
 * Headers (Optional):
 * {
 *   "Authorization": "Bearer {accessToken}"
 * }
 *
 * URL Parameters:
 * - post_id: 댓글을 조회할 게시글 ID
 *
 * Query Parameters:
 * - limit: 조회할 개수 (기본값: 10)
 * - skip: 건너뛸 개수 (기본값: 0)
 */
apiRouter.get("/post/:post_id/comments", (req, res) => {
  try {
    const { post_id } = req.params;
    const limit = parseInt(req.query.limit) || 10;
    const skip = parseInt(req.query.skip) || 0;

    // 1. DB에서 게시글 조회
    const db = router.db;
    const post = db.get("posts").find({ id: post_id }).value();

    // 2. 게시글이 존재하지 않을 때
    if (!post) {
      return res.status(404).json({
        message: "존재하지 않는 게시글입니다.",
      });
    }

    // 3. 현재 로그인한 사용자 확인 (선택적)
    let currentUser = null;
    const authHeader = req.headers.authorization;

    if (authHeader && authHeader.startsWith("Bearer ")) {
      const token = authHeader.substring(7);
      const decoded = verifyToken(token);

      if (decoded) {
        currentUser = db.get("users").find({ _id: decoded._id }).value();
      }
    }

    const currentUserFollowing = currentUser?.following || [];

    // 4. 해당 게시글의 댓글 필터링
    const allComments = db.get("comments").value();
    const postComments = allComments.filter(
      (comment) => comment.postId === post_id
    );

    // 5. createdAt 기준으로 오래된순 정렬 (댓글은 보통 오래된순)
    const sortedComments = postComments.sort((a, b) => {
      return new Date(a.createdAt) - new Date(b.createdAt);
    });

    // 6. 페이지네이션 적용
    const paginatedComments = sortedComments.slice(skip, skip + limit);

    // 7. 각 댓글에 author 정보 추가
    const commentsWithAuthor = paginatedComments
      .map((comment) => {
        const author = db.get("users").find({ _id: comment.authorId }).value();

        if (!author) {
          return null;
        }

        const authorFollowing = author.following || [];
        const authorFollower = author.follower || [];
        const isfollow = currentUserFollowing.includes(author._id);

        return {
          id: comment.id,
          content: comment.content,
          createdAt: comment.createdAt,
          author: {
            _id: author._id,
            username: author.username,
            accountname: author.accountname,
            intro: author.intro || "",
            image: author.image || "",
            isfollow: isfollow,
            following: authorFollowing,
            follower: authorFollower,
            followerCount: authorFollower.length,
            followingCount: authorFollowing.length,
          },
        };
      })
      .filter((comment) => comment !== null); // null 제거

    // 8. 성공 응답
    res.status(200).json({
      comment: commentsWithAuthor,
    });
  } catch (error) {
    console.error("댓글 리스트 조회 오류:", error);
    res.status(500).json({
      message: "서버 오류가 발생했습니다.",
    });
  }
});

/**
 * DELETE /api/post/:post_id/comments/:comment_id - 댓글 삭제 API
 *
 * Headers:
 * {
 *   "Authorization": "Bearer {accessToken}"
 * }
 *
 * URL Parameters:
 * - post_id: 게시글 ID
 * - comment_id: 삭제할 댓글 ID
 */
apiRouter.delete("/post/:post_id/comments/:comment_id", (req, res) => {
  try {
    // 1. Authorization 헤더에서 토큰 추출 및 검증
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        message: "인증 토큰이 필요합니다.",
      });
    }

    const token = authHeader.substring(7);
    const decoded = verifyToken(token);

    if (!decoded) {
      return res.status(401).json({
        message: "유효하지 않은 토큰입니다.",
      });
    }

    const { post_id, comment_id } = req.params;

    // 2. DB에서 게시글 조회
    const db = router.db;
    const post = db.get("posts").find({ id: post_id }).value();

    // 3. 게시글이 존재하지 않을 때
    if (!post) {
      return res.status(404).json({
        message: "존재하지 않는 게시글입니다.",
      });
    }

    // 4. DB에서 댓글 조회
    const comment = db.get("comments").find({ id: comment_id }).value();

    // 5. 댓글이 존재하지 않을 때
    if (!comment) {
      return res.status(404).json({
        message: "댓글이 존재하지 않습니다.",
      });
    }

    // 6. 댓글 작성자 본인 확인
    if (comment.authorId !== decoded._id) {
      return res.status(403).json({
        message: "댓글 작성자만 댓글을 삭제할 수 있습니다.",
      });
    }

    // 7. 댓글 삭제
    db.get("comments").remove({ id: comment_id }).write();

    // 8. 게시글의 commentCount 감소
    const currentCommentCount = post.commentCount || 0;
    db.get("posts")
      .find({ id: post_id })
      .assign({ commentCount: Math.max(0, currentCommentCount - 1) })
      .write();

    // 9. 성공 응답
    res.status(200).json({
      message: "댓글이 삭제되었습니다.",
    });
  } catch (error) {
    console.error("댓글 삭제 오류:", error);
    res.status(500).json({
      message: "서버 오류가 발생했습니다.",
    });
  }
});

/**
 * POST /api/post/:post_id/comments/:comment_id/report - 댓글 신고 API
 *
 * Headers:
 * {
 *   "Authorization": "Bearer {accessToken}"
 * }
 *
 * URL Parameters:
 * - post_id: 게시글 ID
 * - comment_id: 신고할 댓글 ID
 */
apiRouter.post("/post/:post_id/comments/:comment_id/report", (req, res) => {
  try {
    // 1. Authorization 헤더에서 토큰 추출 및 검증
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        message: "인증 토큰이 필요합니다.",
      });
    }

    const token = authHeader.substring(7);
    const decoded = verifyToken(token);

    if (!decoded) {
      return res.status(401).json({
        message: "유효하지 않은 토큰입니다.",
      });
    }

    const { post_id, comment_id } = req.params;

    // 2. DB에서 게시글 조회
    const db = router.db;
    const post = db.get("posts").find({ id: post_id }).value();

    // 3. 게시글이 존재하지 않을 때
    if (!post) {
      return res.status(404).json({
        message: "존재하지 않는 게시글입니다.",
      });
    }

    // 4. DB에서 댓글 조회
    const comment = db.get("comments").find({ id: comment_id }).value();

    // 5. 댓글이 존재하지 않을 때
    if (!comment) {
      return res.status(404).json({
        message: "댓글이 존재하지 않습니다.",
      });
    }

    // 6. 신고 정보 생성
    const newReport = {
      id: generateId(),
      commentId: comment_id,
      postId: post_id,
      reporterId: decoded._id,
      createdAt: new Date().toISOString(),
    };

    // 7. DB에 신고 추가
    db.get("reports").push(newReport).write();

    // 8. 성공 응답
    res.status(200).json({
      report: {
        comment: comment_id,
      },
    });
  } catch (error) {
    console.error("댓글 신고 오류:", error);
    res.status(500).json({
      message: "서버 오류가 발생했습니다.",
    });
  }
});

/**
 * POST /api/product - 상품 등록 API
 *
 * Headers:
 * {
 *   "Authorization": "Bearer {accessToken}"
 * }
 *
 * Request Body:
 * {
 *   "product": {
 *     "itemName": String,
 *     "price": Number (1원 이상),
 *     "link": String,
 *     "itemImage": String
 *   }
 * }
 */
apiRouter.post("/product", (req, res) => {
  try {
    // 1. Authorization 헤더에서 토큰 추출 및 검증
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        message: "인증 토큰이 필요합니다.",
      });
    }

    const token = authHeader.substring(7);
    const decoded = verifyToken(token);

    if (!decoded) {
      return res.status(401).json({
        message: "유효하지 않은 토큰입니다.",
      });
    }

    const { product } = req.body;

    // 2. Request Body 검증
    if (!product) {
      return res.status(400).json({
        message: "잘못된 요청입니다.",
      });
    }

    // 3. 필수 입력사항 체크
    if (
      !product.itemName ||
      product.price === undefined ||
      product.price === null ||
      !product.link ||
      !product.itemImage
    ) {
      return res.status(400).json({
        message: "필수 입력사항을 입력해주세요.",
      });
    }

    // 4. price가 숫자인지 확인
    if (typeof product.price !== "number" || isNaN(product.price)) {
      return res.status(400).json({
        message: "가격은 숫자로 입력하셔야 합니다.",
      });
    }

    // 5. price가 1원 이상인지 확인
    if (product.price < 1) {
      return res.status(400).json({
        message: "가격은 1원 이상이어야 합니다.",
      });
    }

    // 6. DB에서 작성자 정보 조회
    const db = router.db;
    const author = db.get("users").find({ _id: decoded._id }).value();

    if (!author) {
      return res.status(404).json({
        message: "사용자를 찾을 수 없습니다.",
      });
    }

    // 7. 새 상품 생성
    const newProduct = {
      id: generateId(),
      itemName: product.itemName,
      price: product.price,
      link: product.link,
      itemImage: product.itemImage,
      authorId: author._id,
      createdAt: new Date().toISOString(),
    };

    // 8. DB에 상품 추가
    db.get("products").push(newProduct).write();

    // 9. author 정보 구성
    const authorFollowing = author.following || [];
    const authorFollower = author.follower || [];

    const productResponse = {
      id: newProduct.id,
      itemName: newProduct.itemName,
      price: newProduct.price,
      link: newProduct.link,
      itemImage: newProduct.itemImage,
      author: {
        _id: author._id,
        username: author.username,
        accountname: author.accountname,
        intro: author.intro || "",
        image: author.image || "",
        isfollow: false, // 자기 자신의 상품이므로 false
        following: authorFollowing,
        follower: authorFollower,
        followerCount: authorFollower.length,
        followingCount: authorFollowing.length,
      },
    };

    // 10. 성공 응답
    res.status(201).json({
      product: productResponse,
    });
  } catch (error) {
    console.error("상품 등록 오류:", error);
    res.status(500).json({
      message: "서버 오류가 발생했습니다.",
    });
  }
});

/**
 * GET /api/product/:accountname - 상품 리스트 조회 API
 *
 * Headers (Optional):
 * {
 *   "Authorization": "Bearer {accessToken}"
 * }
 *
 * URL Parameters:
 * - accountname: 조회할 사용자의 계정ID
 *
 * Query Parameters:
 * - limit: 조회할 개수 (기본값: 10)
 * - skip: 건너뛸 개수 (기본값: 0)
 */
apiRouter.get("/product/:accountname", (req, res) => {
  try {
    const { accountname } = req.params;
    const limit = parseInt(req.query.limit) || 10;
    const skip = parseInt(req.query.skip) || 0;

    // 1. DB에서 accountname으로 사용자 찾기
    const db = router.db;
    const targetUser = db
      .get("users")
      .find({ accountname: accountname })
      .value();

    // 2. 사용자가 존재하지 않을 때도 빈 배열 반환
    if (!targetUser) {
      return res.status(200).json({
        data: 0,
        product: [],
      });
    }

    // 3. 현재 로그인한 사용자 확인 (선택적)
    let currentUser = null;
    const authHeader = req.headers.authorization;

    if (authHeader && authHeader.startsWith("Bearer ")) {
      const token = authHeader.substring(7);
      const decoded = verifyToken(token);

      if (decoded) {
        currentUser = db.get("users").find({ _id: decoded._id }).value();
      }
    }

    const currentUserFollowing = currentUser?.following || [];

    // 4. 모든 상품 가져오기
    const allProducts = db.get("products").value();

    // 5. 해당 사용자의 상품만 필터링
    const userProducts = allProducts.filter(
      (product) => product.authorId === targetUser._id
    );

    // 6. 전체 상품 개수
    const totalCount = userProducts.length;

    // 7. createdAt 기준으로 최신순 정렬
    const sortedProducts = userProducts.sort((a, b) => {
      return new Date(b.createdAt) - new Date(a.createdAt);
    });

    // 8. 페이지네이션 적용
    const paginatedProducts = sortedProducts.slice(skip, skip + limit);

    // 9. 각 상품에 author 정보 추가
    const authorFollowing = targetUser.following || [];
    const authorFollower = targetUser.follower || [];
    const isfollow = currentUserFollowing.includes(targetUser._id);

    const productsWithAuthor = paginatedProducts.map((product) => {
      return {
        id: product.id,
        itemName: product.itemName,
        price: product.price,
        link: product.link,
        itemImage: product.itemImage,
        author: {
          _id: targetUser._id,
          username: targetUser.username,
          accountname: targetUser.accountname,
          intro: targetUser.intro || "",
          image: targetUser.image || "",
          isfollow: isfollow,
          following: authorFollowing,
          follower: authorFollower,
          followerCount: authorFollower.length,
          followingCount: authorFollowing.length,
        },
      };
    });

    // 10. 성공 응답
    res.status(200).json({
      count: totalCount,
      product: productsWithAuthor,
    });
  } catch (error) {
    console.error("상품 리스트 조회 오류:", error);
    res.status(500).json({
      message: "서버 오류가 발생했습니다.",
    });
  }
});

/**
 * GET /api/product/detail/:product_id - 상품 상세 조회 API
 *
 * Headers (Optional):
 * {
 *   "Authorization": "Bearer {accessToken}"
 * }
 *
 * URL Parameters:
 * - product_id: 조회할 상품 ID
 */
apiRouter.get("/product/detail/:product_id", (req, res) => {
  try {
    const { product_id } = req.params;

    // 1. DB에서 상품 조회
    const db = router.db;
    const product = db.get("products").find({ id: product_id }).value();

    // 2. 상품이 존재하지 않을 때
    if (!product) {
      return res.status(404).json({
        message: "존재하지 않는 상품입니다.",
      });
    }

    // 3. 작성자 정보 조회
    const author = db.get("users").find({ _id: product.authorId }).value();

    if (!author) {
      return res.status(404).json({
        message: "작성자를 찾을 수 없습니다.",
      });
    }

    // 4. 현재 로그인한 사용자 확인 (선택적)
    let currentUser = null;
    const authHeader = req.headers.authorization;

    if (authHeader && authHeader.startsWith("Bearer ")) {
      const token = authHeader.substring(7);
      const decoded = verifyToken(token);

      if (decoded) {
        currentUser = db.get("users").find({ _id: decoded._id }).value();
      }
    }

    const currentUserFollowing = currentUser?.following || [];

    // 5. author 정보 구성
    const authorFollowing = author.following || [];
    const authorFollower = author.follower || [];
    const isfollow = currentUserFollowing.includes(author._id);

    const productDetail = {
      id: product.id,
      itemName: product.itemName,
      price: product.price,
      link: product.link,
      itemImage: product.itemImage,
      author: {
        _id: author._id,
        username: author.username,
        accountname: author.accountname,
        intro: author.intro || "",
        image: author.image || "",
        isfollow: isfollow,
        following: authorFollowing,
        follower: authorFollower,
        followerCount: authorFollower.length,
        followingCount: authorFollowing.length,
      },
    };

    // 6. 성공 응답
    res.status(200).json({
      product: productDetail,
    });
  } catch (error) {
    console.error("상품 상세 조회 오류:", error);
    res.status(500).json({
      message: "서버 오류가 발생했습니다.",
    });
  }
});

/**
 * PUT /api/product/:product_id - 상품 수정 API
 *
 * Headers:
 * {
 *   "Authorization": "Bearer {accessToken}"
 * }
 *
 * URL Parameters:
 * - product_id: 수정할 상품 ID
 *
 * Request Body:
 * {
 *   "product": {
 *     "itemName": String,
 *     "price": Number,
 *     "link": String,
 *     "itemImage": String
 *   }
 * }
 */
apiRouter.put("/product/:product_id", (req, res) => {
  try {
    // 1. Authorization 헤더에서 토큰 추출 및 검증
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        message: "인증 토큰이 필요합니다.",
      });
    }

    const token = authHeader.substring(7);
    const decoded = verifyToken(token);

    if (!decoded) {
      return res.status(401).json({
        message: "유효하지 않은 토큰입니다.",
      });
    }

    const { product_id } = req.params;
    const { product } = req.body;

    // 2. Request Body 검증
    if (!product) {
      return res.status(400).json({
        message: "잘못된 요청입니다.",
      });
    }

    // 3. DB에서 상품 조회
    const db = router.db;
    const existingProduct = db.get("products").find({ id: product_id }).value();

    // 4. 상품이 존재하지 않을 때
    if (!existingProduct) {
      return res.status(404).json({
        message: "등록된 상품이 없습니다.",
      });
    }

    // 5. 작성자 본인 확인
    if (existingProduct.authorId !== decoded._id) {
      return res.status(403).json({
        message: "잘못된 요청입니다. 로그인 정보를 확인하세요.",
      });
    }

    // 6. price 검증 (제공된 경우)
    if (product.price !== undefined) {
      if (typeof product.price !== "number" || isNaN(product.price)) {
        return res.status(400).json({
          message: "가격은 숫자로 입력하셔야 합니다.",
        });
      }
      if (product.price < 1) {
        return res.status(400).json({
          message: "가격은 1원 이상이어야 합니다.",
        });
      }
    }

    // 7. 상품 업데이트
    const updatedData = {
      itemName:
        product.itemName !== undefined
          ? product.itemName
          : existingProduct.itemName,
      price:
        product.price !== undefined ? product.price : existingProduct.price,
      link: product.link !== undefined ? product.link : existingProduct.link,
      itemImage:
        product.itemImage !== undefined
          ? product.itemImage
          : existingProduct.itemImage,
    };

    db.get("products").find({ id: product_id }).assign(updatedData).write();

    // 8. 업데이트된 상품 다시 조회
    const updatedProduct = db.get("products").find({ id: product_id }).value();

    // 9. 작성자 정보 조회
    const author = db
      .get("users")
      .find({ _id: updatedProduct.authorId })
      .value();

    if (!author) {
      return res.status(404).json({
        message: "작성자를 찾을 수 없습니다.",
      });
    }

    // 10. author 정보 구성
    const authorFollowing = author.following || [];
    const authorFollower = author.follower || [];

    const productDetail = {
      id: updatedProduct.id,
      itemName: updatedProduct.itemName,
      price: updatedProduct.price,
      link: updatedProduct.link,
      itemImage: updatedProduct.itemImage,
      author: {
        _id: author._id,
        username: author.username,
        accountname: author.accountname,
        intro: author.intro || "",
        image: author.image || "",
        isfollow: false, // 자기 자신의 상품이므로 false
        following: authorFollowing,
        follower: authorFollower,
        followerCount: authorFollower.length,
        followingCount: authorFollowing.length,
      },
    };

    // 11. 성공 응답
    res.status(200).json({
      product: productDetail,
    });
  } catch (error) {
    console.error("상품 수정 오류:", error);
    res.status(500).json({
      message: "서버 오류가 발생했습니다.",
    });
  }
});

/**
 * DELETE /api/product/:product_id - 상품 삭제 API
 *
 * Headers:
 * {
 *   "Authorization": "Bearer {accessToken}"
 * }
 *
 * URL Parameters:
 * - product_id: 삭제할 상품 ID
 */
apiRouter.delete("/product/:product_id", (req, res) => {
  try {
    // 1. Authorization 헤더에서 토큰 추출 및 검증
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        message: "인증 토큰이 필요합니다.",
      });
    }

    const token = authHeader.substring(7);
    const decoded = verifyToken(token);

    if (!decoded) {
      return res.status(401).json({
        message: "유효하지 않은 토큰입니다.",
      });
    }

    const { product_id } = req.params;

    // 2. DB에서 상품 조회
    const db = router.db;
    const existingProduct = db.get("products").find({ id: product_id }).value();

    // 3. 상품이 존재하지 않을 때
    if (!existingProduct) {
      return res.status(404).json({
        message: "등록된 상품이 없습니다.",
      });
    }

    // 4. 작성자 본인 확인
    if (existingProduct.authorId !== decoded._id) {
      return res.status(403).json({
        message: "잘못된 요청입니다. 로그인 정보를 확인하세요.",
      });
    }

    // 5. 상품 삭제
    db.get("products").remove({ id: product_id }).write();

    // 6. 성공 응답
    res.status(200).json({
      message: "삭제되었습니다.",
    });
  } catch (error) {
    console.error("상품 삭제 오류:", error);
    res.status(500).json({
      message: "서버 오류가 발생했습니다.",
    });
  }
});

// ============================================
// json-server 라우터 (REST API 자동 생성)
// ============================================
apiRouter.use(router);

// ============================================
// API 라우터를 /api prefix로 마운트
// ============================================
// Swagger UI
// ============================================
app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// ============================================
app.use("/api", apiRouter);

// ============================================
// 서버 시작
// ============================================
app.listen(PORT, () => {
  console.log(`🚀 Server is running on http://localhost:${PORT}`);
  console.log(`📚 API Documentation: http://localhost:${PORT}/api-docs`);
  console.log(`📚 Available API endpoints:`);
});
