const swaggerJSDoc = require('swagger-jsdoc');

const swaggerDefinition = {
  openapi: '3.0.0',
  info: {
    title: 'Alyac Market API',
    version: '1.0.0',
    description: 'Alyac Market Server REST API Documentation',
    contact: {
      name: 'API Support',
    },
  },
  servers: [
    {
      url: 'http://localhost:3000',
      description: 'Development server',
    },
  ],
  components: {
    securitySchemes: {
      bearerAuth: {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
      },
    },
    schemas: {
      User: {
        type: 'object',
        properties: {
          _id: { type: 'string', example: '1763716649507farib3dpj' },
          username: { type: 'string', example: 'test' },
          email: { type: 'string', format: 'email', example: 'test@test.com' },
          accountname: { type: 'string', example: 'test1234' },
          intro: { type: 'string', example: '' },
          image: { type: 'string', example: '' },
          following: { type: 'array', items: { type: 'string' } },
          follower: { type: 'array', items: { type: 'string' } },
          followerCount: { type: 'number', example: 0 },
          followingCount: { type: 'number', example: 0 },
        },
      },
      UserRegister: {
        type: 'object',
        required: ['user'],
        properties: {
          user: {
            type: 'object',
            required: ['username', 'email', 'password', 'accountname'],
            properties: {
              username: { type: 'string', example: 'test' },
              email: { type: 'string', format: 'email', example: 'test@test.com' },
              password: { type: 'string', minLength: 6, example: '123456' },
              accountname: { type: 'string', pattern: '^[a-zA-Z0-9_.]+$', example: 'test1234' },
              intro: { type: 'string', example: '' },
              image: { type: 'string', example: '' },
            },
          },
        },
      },
      UserLogin: {
        type: 'object',
        required: ['user'],
        properties: {
          user: {
            type: 'object',
            required: ['email', 'password'],
            properties: {
              email: { type: 'string', format: 'email', example: 'test@test.com' },
              password: { type: 'string', example: '123456' },
            },
          },
        },
      },
      Post: {
        type: 'object',
        properties: {
          id: { type: 'string', example: '176577311389996cukkcwq' },
          content: { type: 'string', example: '테스트 내용' },
          image: { type: 'string', example: 'uploadFiles/1769738162748.png,uploadFiles/1769738168158.png' },
          createdAt: { type: 'string', format: 'date-time' },
          updatedAt: { type: 'string', format: 'date-time' },
          hearted: { type: 'boolean', example: false },
          heartCount: { type: 'number', example: 0 },
          commentCount: { type: 'number', example: 0 },
          authorId: { type: 'string', example: '1763716649507farib3dpj' },
          author: { $ref: '#/components/schemas/User' },
        },
      },
      PostCreate: {
        type: 'object',
        required: ['post'],
        properties: {
          post: {
            type: 'object',
            properties: {
              content: { type: 'string', example: '테스트 내용' },
              image: { type: 'string', example: 'uploadFiles/image1.png,uploadFiles/image2.png' },
            },
          },
        },
      },
      Comment: {
        type: 'object',
        properties: {
          id: { type: 'string', example: '1765777020631t6gg2xja0' },
          content: { type: 'string', example: '댓글 내용' },
          createdAt: { type: 'string', format: 'date-time' },
          postId: { type: 'string', example: '1765773135857jt36deem4' },
          authorId: { type: 'string', example: '1763716649507farib3dpj' },
          author: { $ref: '#/components/schemas/User' },
        },
      },
      CommentCreate: {
        type: 'object',
        required: ['comment'],
        properties: {
          comment: {
            type: 'object',
            required: ['content'],
            properties: {
              content: { type: 'string', example: '댓글 내용' },
            },
          },
        },
      },
      Product: {
        type: 'object',
        properties: {
          id: { type: 'string', example: '1769758350286v8piw6asl' },
          itemName: { type: 'string', example: '테스트 상품' },
          price: { type: 'number', minimum: 1, example: 10000 },
          link: { type: 'string', format: 'uri', example: 'http://naver.com' },
          itemImage: { type: 'string', example: 'uploadFiles/1769758339805.png' },
          authorId: { type: 'string', example: '17696615580476a60p18bu' },
          createdAt: { type: 'string', format: 'date-time' },
          author: { $ref: '#/components/schemas/User' },
        },
      },
      ProductCreate: {
        type: 'object',
        required: ['product'],
        properties: {
          product: {
            type: 'object',
            required: ['itemName', 'price', 'link', 'itemImage'],
            properties: {
              itemName: { type: 'string', example: '테스트 상품' },
              price: { type: 'number', minimum: 1, example: 10000 },
              link: { type: 'string', format: 'uri', example: 'http://naver.com' },
              itemImage: { type: 'string', example: 'uploadFiles/image.png' },
            },
          },
        },
      },
      Error: {
        type: 'object',
        properties: {
          message: { type: 'string', example: 'Error message' },
        },
      },
    },
  },
  paths: {
    '/api/image/uploadfile': {
      post: {
        tags: ['Image'],
        summary: 'Upload single image',
        description: 'Upload a single image file',
        requestBody: {
          required: true,
          content: {
            'multipart/form-data': {
              schema: {
                type: 'object',
                properties: {
                  image: {
                    type: 'string',
                    format: 'binary',
                  },
                },
              },
            },
          },
        },
        responses: {
          200: {
            description: 'Image uploaded successfully',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    fieldname: { type: 'string' },
                    originalname: { type: 'string' },
                    encoding: { type: 'string' },
                    mimetype: { type: 'string' },
                    destination: { type: 'string' },
                    filename: { type: 'string' },
                    path: { type: 'string' },
                    size: { type: 'number' },
                  },
                },
              },
            },
          },
          400: { description: 'No file uploaded' },
          500: { description: 'Server error' },
        },
      },
    },
    '/api/image/uploadfiles': {
      post: {
        tags: ['Image'],
        summary: 'Upload multiple images',
        description: 'Upload up to 10 images at once',
        requestBody: {
          required: true,
          content: {
            'multipart/form-data': {
              schema: {
                type: 'object',
                properties: {
                  image: {
                    type: 'array',
                    items: {
                      type: 'string',
                      format: 'binary',
                    },
                    maxItems: 10,
                  },
                },
              },
            },
          },
        },
        responses: {
          200: {
            description: 'Images uploaded successfully',
            content: {
              'application/json': {
                schema: {
                  type: 'array',
                  items: {
                    type: 'object',
                    properties: {
                      fieldname: { type: 'string' },
                      originalname: { type: 'string' },
                      encoding: { type: 'string' },
                      mimetype: { type: 'string' },
                      destination: { type: 'string' },
                      filename: { type: 'string' },
                      path: { type: 'string' },
                      size: { type: 'number' },
                    },
                  },
                },
              },
            },
          },
          400: { description: 'No files uploaded' },
          500: { description: 'Server error' },
        },
      },
    },
    '/api/user': {
      post: {
        tags: ['User'],
        summary: 'User registration',
        description: 'Register a new user',
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/UserRegister' },
            },
          },
        },
        responses: {
          201: {
            description: 'User registered successfully',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    message: { type: 'string', example: '회원가입 성공' },
                    user: { $ref: '#/components/schemas/User' },
                  },
                },
              },
            },
          },
          400: { description: 'Validation error', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
          500: { description: 'Server error' },
        },
      },
      put: {
        tags: ['User'],
        summary: 'Update user profile',
        description: 'Update logged-in user profile',
        security: [{ bearerAuth: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  user: {
                    type: 'object',
                    properties: {
                      username: { type: 'string' },
                      accountname: { type: 'string' },
                      intro: { type: 'string' },
                      image: { type: 'string' },
                    },
                  },
                },
              },
            },
          },
        },
        responses: {
          200: {
            description: 'User updated successfully',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    user: { $ref: '#/components/schemas/User' },
                  },
                },
              },
            },
          },
          400: { description: 'Validation error' },
          401: { description: 'Unauthorized' },
          500: { description: 'Server error' },
        },
      },
    },
    '/api/user/signin': {
      post: {
        tags: ['User'],
        summary: 'User login',
        description: 'Login with email and password',
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/UserLogin' },
            },
          },
        },
        responses: {
          200: {
            description: 'Login successful',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    user: {
                      allOf: [
                        { $ref: '#/components/schemas/User' },
                        {
                          type: 'object',
                          properties: {
                            accessToken: { type: 'string' },
                            refreshToken: { type: 'string' },
                          },
                        },
                      ],
                    },
                  },
                },
              },
            },
          },
          400: { description: 'Missing fields' },
          422: { description: 'Invalid credentials' },
          500: { description: 'Server error' },
        },
      },
    },
    '/api/user/refresh': {
      post: {
        tags: ['User'],
        summary: 'Refresh access token',
        description: 'Get new access token using refresh token',
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                required: ['refreshToken'],
                properties: {
                  refreshToken: {
                    type: 'string',
                    description: 'Valid refresh token',
                    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
                  },
                },
              },
            },
          },
        },
        responses: {
          200: {
            description: 'Token refreshed successfully',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    accessToken: {
                      type: 'string',
                      description: 'New access token',
                      example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
                    },
                    refreshToken: {
                      type: 'string',
                      description: 'New refresh token',
                      example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
                    },
                  },
                },
              },
            },
          },
          400: { description: 'Refresh token required' },
          401: { description: 'Invalid or expired refresh token' },
          404: { description: 'User not found' },
          500: { description: 'Server error' },
        },
      },
    },
    '/api/user/myinfo': {
      get: {
        tags: ['User'],
        summary: 'Get my info',
        description: 'Get logged-in user information',
        security: [{ bearerAuth: [] }],
        responses: {
          200: {
            description: 'User info retrieved successfully',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    user: { $ref: '#/components/schemas/User' },
                  },
                },
              },
            },
          },
          401: { description: 'Unauthorized' },
          404: { description: 'User not found' },
          500: { description: 'Server error' },
        },
      },
    },
    '/api/user/checktoken': {
      get: {
        tags: ['User'],
        summary: 'Check token validity',
        description: 'Validate JWT token',
        security: [{ bearerAuth: [] }],
        responses: {
          200: {
            description: 'Token validation result',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    isValid: { type: 'boolean' },
                  },
                },
              },
            },
          },
        },
      },
    },
    '/api/user/emailvalid': {
      post: {
        tags: ['User'],
        summary: 'Check email duplication',
        description: 'Validate if email is already registered',
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  user: {
                    type: 'object',
                    properties: {
                      email: { type: 'string', format: 'email' },
                    },
                  },
                },
              },
            },
          },
        },
        responses: {
          200: {
            description: 'Email validation result',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    ok: { type: 'boolean' },
                    message: { type: 'string' },
                  },
                },
              },
            },
          },
          400: { description: 'Validation error' },
          500: { description: 'Server error' },
        },
      },
    },
    '/api/user/accountnamevalid': {
      post: {
        tags: ['User'],
        summary: 'Check accountname duplication',
        description: 'Validate if accountname is already registered',
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  user: {
                    type: 'object',
                    properties: {
                      accountname: { type: 'string' },
                    },
                  },
                },
              },
            },
          },
        },
        responses: {
          200: {
            description: 'Accountname validation result',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    ok: { type: 'boolean' },
                    message: { type: 'string' },
                  },
                },
              },
            },
          },
          400: { description: 'Validation error' },
          500: { description: 'Server error' },
        },
      },
    },
    '/api/user/searchuser': {
      get: {
        tags: ['User'],
        summary: 'Search users',
        description: 'Search users by username or accountname',
        parameters: [
          {
            in: 'query',
            name: 'keyword',
            schema: { type: 'string' },
            description: 'Search keyword',
          },
        ],
        responses: {
          200: {
            description: 'Search results',
            content: {
              'application/json': {
                schema: {
                  type: 'array',
                  items: { $ref: '#/components/schemas/User' },
                },
              },
            },
          },
          500: { description: 'Server error' },
        },
      },
    },
    '/api/profile/{accountname}': {
      get: {
        tags: ['Profile'],
        summary: 'Get user profile',
        description: 'Get user profile by accountname',
        security: [{ bearerAuth: [] }, {}],
        parameters: [
          {
            in: 'path',
            name: 'accountname',
            required: true,
            schema: { type: 'string' },
            description: 'User accountname',
          },
        ],
        responses: {
          200: {
            description: 'User profile',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    profile: {
                      allOf: [
                        { $ref: '#/components/schemas/User' },
                        {
                          type: 'object',
                          properties: {
                            isfollow: { type: 'boolean' },
                          },
                        },
                      ],
                    },
                  },
                },
              },
            },
          },
          404: { description: 'User not found' },
          500: { description: 'Server error' },
        },
      },
    },
    '/api/profile/{accountname}/follow': {
      post: {
        tags: ['Profile'],
        summary: 'Follow user',
        description: 'Follow a user',
        security: [{ bearerAuth: [] }],
        parameters: [
          {
            in: 'path',
            name: 'accountname',
            required: true,
            schema: { type: 'string' },
            description: 'User accountname to follow',
          },
        ],
        responses: {
          200: {
            description: 'Follow successful',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    profile: { $ref: '#/components/schemas/User' },
                  },
                },
              },
            },
          },
          400: { description: 'Cannot follow self' },
          401: { description: 'Unauthorized' },
          404: { description: 'User not found' },
          500: { description: 'Server error' },
        },
      },
    },
    '/api/profile/{accountname}/unfollow': {
      delete: {
        tags: ['Profile'],
        summary: 'Unfollow user',
        description: 'Unfollow a user',
        security: [{ bearerAuth: [] }],
        parameters: [
          {
            in: 'path',
            name: 'accountname',
            required: true,
            schema: { type: 'string' },
            description: 'User accountname to unfollow',
          },
        ],
        responses: {
          200: {
            description: 'Unfollow successful',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    profile: { $ref: '#/components/schemas/User' },
                  },
                },
              },
            },
          },
          401: { description: 'Unauthorized' },
          404: { description: 'User not found' },
          500: { description: 'Server error' },
        },
      },
    },
    '/api/profile/{accountname}/following': {
      get: {
        tags: ['Profile'],
        summary: 'Get following list',
        description: 'Get list of users that this user is following',
        security: [{ bearerAuth: [] }, {}],
        parameters: [
          {
            in: 'path',
            name: 'accountname',
            required: true,
            schema: { type: 'string' },
          },
          {
            in: 'query',
            name: 'limit',
            schema: { type: 'number', default: 10 },
          },
          {
            in: 'query',
            name: 'skip',
            schema: { type: 'number', default: 0 },
          },
        ],
        responses: {
          200: {
            description: 'Following list',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    following: {
                      type: 'array',
                      items: { $ref: '#/components/schemas/User' },
                    },
                  },
                },
              },
            },
          },
          404: { description: 'User not found' },
          500: { description: 'Server error' },
        },
      },
    },
    '/api/profile/{accountname}/follower': {
      get: {
        tags: ['Profile'],
        summary: 'Get follower list',
        description: 'Get list of users following this user',
        security: [{ bearerAuth: [] }, {}],
        parameters: [
          {
            in: 'path',
            name: 'accountname',
            required: true,
            schema: { type: 'string' },
          },
          {
            in: 'query',
            name: 'limit',
            schema: { type: 'number', default: 10 },
          },
          {
            in: 'query',
            name: 'skip',
            schema: { type: 'number', default: 0 },
          },
        ],
        responses: {
          200: {
            description: 'Follower list',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    follower: {
                      type: 'array',
                      items: { $ref: '#/components/schemas/User' },
                    },
                  },
                },
              },
            },
          },
          404: { description: 'User not found' },
          500: { description: 'Server error' },
        },
      },
    },
    '/api/post': {
      post: {
        tags: ['Post'],
        summary: 'Create post',
        description: 'Create a new post',
        security: [{ bearerAuth: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/PostCreate' },
            },
          },
        },
        responses: {
          201: {
            description: 'Post created successfully',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    post: { $ref: '#/components/schemas/Post' },
                  },
                },
              },
            },
          },
          400: { description: 'Validation error' },
          401: { description: 'Unauthorized' },
          404: { description: 'Author not found' },
          500: { description: 'Server error' },
        },
      },
      get: {
        tags: ['Post'],
        summary: 'Get all posts',
        description: 'Get paginated list of all posts',
        security: [{ bearerAuth: [] }, {}],
        parameters: [
          {
            in: 'query',
            name: 'limit',
            schema: { type: 'number', default: 10 },
          },
          {
            in: 'query',
            name: 'skip',
            schema: { type: 'number', default: 0 },
          },
        ],
        responses: {
          200: {
            description: 'List of posts',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    posts: {
                      type: 'array',
                      items: { $ref: '#/components/schemas/Post' },
                    },
                  },
                },
              },
            },
          },
          500: { description: 'Server error' },
        },
      },
    },
    '/api/post/feed': {
      get: {
        tags: ['Post'],
        summary: 'Get following feed',
        description: 'Get posts from users you follow',
        security: [{ bearerAuth: [] }],
        parameters: [
          {
            in: 'query',
            name: 'limit',
            schema: { type: 'number', default: 10 },
          },
          {
            in: 'query',
            name: 'skip',
            schema: { type: 'number', default: 0 },
          },
        ],
        responses: {
          200: {
            description: 'Feed posts',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    posts: {
                      type: 'array',
                      items: { $ref: '#/components/schemas/Post' },
                    },
                  },
                },
              },
            },
          },
          401: { description: 'Unauthorized' },
          404: { description: 'User not found' },
          500: { description: 'Server error' },
        },
      },
    },
    '/api/post/{post_id}': {
      get: {
        tags: ['Post'],
        summary: 'Get post details',
        description: 'Get details of a specific post',
        security: [{ bearerAuth: [] }, {}],
        parameters: [
          {
            in: 'path',
            name: 'post_id',
            required: true,
            schema: { type: 'string' },
          },
        ],
        responses: {
          200: {
            description: 'Post details',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    post: { $ref: '#/components/schemas/Post' },
                  },
                },
              },
            },
          },
          404: { description: 'Post not found' },
          500: { description: 'Server error' },
        },
      },
      put: {
        tags: ['Post'],
        summary: 'Update post',
        description: 'Update post (author only)',
        security: [{ bearerAuth: [] }],
        parameters: [
          {
            in: 'path',
            name: 'post_id',
            required: true,
            schema: { type: 'string' },
          },
        ],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  post: {
                    type: 'object',
                    properties: {
                      content: { type: 'string' },
                      image: { type: 'string' },
                    },
                  },
                },
              },
            },
          },
        },
        responses: {
          200: {
            description: 'Post updated successfully',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    post: { $ref: '#/components/schemas/Post' },
                  },
                },
              },
            },
          },
          401: { description: 'Unauthorized' },
          403: { description: 'Forbidden - not the author' },
          404: { description: 'Post not found' },
          500: { description: 'Server error' },
        },
      },
      delete: {
        tags: ['Post'],
        summary: 'Delete post',
        description: 'Delete post (author only)',
        security: [{ bearerAuth: [] }],
        parameters: [
          {
            in: 'path',
            name: 'post_id',
            required: true,
            schema: { type: 'string' },
          },
        ],
        responses: {
          200: {
            description: 'Post deleted successfully',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    message: { type: 'string', example: '삭제되었습니다.' },
                  },
                },
              },
            },
          },
          401: { description: 'Unauthorized' },
          403: { description: 'Forbidden - not the author' },
          404: { description: 'Post not found' },
          500: { description: 'Server error' },
        },
      },
    },
    '/api/post/{accountname}/userpost': {
      get: {
        tags: ['Post'],
        summary: 'Get user posts',
        description: 'Get all posts by specific user',
        security: [{ bearerAuth: [] }, {}],
        parameters: [
          {
            in: 'path',
            name: 'accountname',
            required: true,
            schema: { type: 'string' },
          },
          {
            in: 'query',
            name: 'limit',
            schema: { type: 'number', default: 10 },
          },
          {
            in: 'query',
            name: 'skip',
            schema: { type: 'number', default: 0 },
          },
        ],
        responses: {
          200: {
            description: 'User posts',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    post: {
                      type: 'array',
                      items: { $ref: '#/components/schemas/Post' },
                    },
                  },
                },
              },
            },
          },
          404: { description: 'User not found' },
          500: { description: 'Server error' },
        },
      },
    },
    '/api/post/{post_id}/report': {
      post: {
        tags: ['Post'],
        summary: 'Report post',
        description: 'Report a post',
        security: [{ bearerAuth: [] }],
        parameters: [
          {
            in: 'path',
            name: 'post_id',
            required: true,
            schema: { type: 'string' },
          },
        ],
        responses: {
          200: {
            description: 'Post reported successfully',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    report: {
                      type: 'object',
                      properties: {
                        post: { type: 'string' },
                      },
                    },
                  },
                },
              },
            },
          },
          401: { description: 'Unauthorized' },
          404: { description: 'Post not found' },
          500: { description: 'Server error' },
        },
      },
    },
    '/api/post/{post_id}/heart': {
      post: {
        tags: ['Post'],
        summary: 'Like/Unlike post (toggle)',
        description: 'Toggle like status for a post',
        security: [{ bearerAuth: [] }],
        parameters: [
          {
            in: 'path',
            name: 'post_id',
            required: true,
            schema: { type: 'string' },
          },
        ],
        responses: {
          200: {
            description: 'Like status toggled',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    post: { $ref: '#/components/schemas/Post' },
                  },
                },
              },
            },
          },
          401: { description: 'Unauthorized' },
          404: { description: 'Post not found' },
          500: { description: 'Server error' },
        },
      },
    },
    '/api/post/{post_id}/unheart': {
      delete: {
        tags: ['Post'],
        summary: 'Unlike post',
        description: 'Remove like from a post',
        security: [{ bearerAuth: [] }],
        parameters: [
          {
            in: 'path',
            name: 'post_id',
            required: true,
            schema: { type: 'string' },
          },
        ],
        responses: {
          200: {
            description: 'Post unliked',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    post: { $ref: '#/components/schemas/Post' },
                  },
                },
              },
            },
          },
          401: { description: 'Unauthorized' },
          404: { description: 'Post not found' },
          500: { description: 'Server error' },
        },
      },
    },
    '/api/post/{post_id}/comments': {
      post: {
        tags: ['Comment'],
        summary: 'Create comment',
        description: 'Add a comment to a post',
        security: [{ bearerAuth: [] }],
        parameters: [
          {
            in: 'path',
            name: 'post_id',
            required: true,
            schema: { type: 'string' },
          },
        ],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/CommentCreate' },
            },
          },
        },
        responses: {
          201: {
            description: 'Comment created successfully',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    comment: { $ref: '#/components/schemas/Comment' },
                  },
                },
              },
            },
          },
          400: { description: 'Validation error' },
          401: { description: 'Unauthorized' },
          404: { description: 'Post not found' },
          500: { description: 'Server error' },
        },
      },
      get: {
        tags: ['Comment'],
        summary: 'Get post comments',
        description: 'Get all comments for a post',
        security: [{ bearerAuth: [] }, {}],
        parameters: [
          {
            in: 'path',
            name: 'post_id',
            required: true,
            schema: { type: 'string' },
          },
          {
            in: 'query',
            name: 'limit',
            schema: { type: 'number', default: 10 },
          },
          {
            in: 'query',
            name: 'skip',
            schema: { type: 'number', default: 0 },
          },
        ],
        responses: {
          200: {
            description: 'List of comments',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    comment: {
                      type: 'array',
                      items: { $ref: '#/components/schemas/Comment' },
                    },
                  },
                },
              },
            },
          },
          404: { description: 'Post not found' },
          500: { description: 'Server error' },
        },
      },
    },
    '/api/post/{post_id}/comments/{comment_id}': {
      delete: {
        tags: ['Comment'],
        summary: 'Delete comment',
        description: 'Delete a comment (author only)',
        security: [{ bearerAuth: [] }],
        parameters: [
          {
            in: 'path',
            name: 'post_id',
            required: true,
            schema: { type: 'string' },
          },
          {
            in: 'path',
            name: 'comment_id',
            required: true,
            schema: { type: 'string' },
          },
        ],
        responses: {
          200: {
            description: 'Comment deleted successfully',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    message: { type: 'string', example: '댓글이 삭제되었습니다.' },
                  },
                },
              },
            },
          },
          401: { description: 'Unauthorized' },
          403: { description: 'Forbidden - not the author' },
          404: { description: 'Post or comment not found' },
          500: { description: 'Server error' },
        },
      },
    },
    '/api/post/{post_id}/comments/{comment_id}/report': {
      post: {
        tags: ['Comment'],
        summary: 'Report comment',
        description: 'Report a comment',
        security: [{ bearerAuth: [] }],
        parameters: [
          {
            in: 'path',
            name: 'post_id',
            required: true,
            schema: { type: 'string' },
          },
          {
            in: 'path',
            name: 'comment_id',
            required: true,
            schema: { type: 'string' },
          },
        ],
        responses: {
          200: {
            description: 'Comment reported successfully',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    report: {
                      type: 'object',
                      properties: {
                        comment: { type: 'string' },
                      },
                    },
                  },
                },
              },
            },
          },
          401: { description: 'Unauthorized' },
          404: { description: 'Post or comment not found' },
          500: { description: 'Server error' },
        },
      },
    },
    '/api/product': {
      post: {
        tags: ['Product'],
        summary: 'Create product',
        description: 'Create a new product',
        security: [{ bearerAuth: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/ProductCreate' },
            },
          },
        },
        responses: {
          201: {
            description: 'Product created successfully',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    product: { $ref: '#/components/schemas/Product' },
                  },
                },
              },
            },
          },
          400: { description: 'Validation error' },
          401: { description: 'Unauthorized' },
          404: { description: 'Author not found' },
          500: { description: 'Server error' },
        },
      },
    },
    '/api/product/{accountname}': {
      get: {
        tags: ['Product'],
        summary: 'Get user products',
        description: 'Get all products by specific user',
        security: [{ bearerAuth: [] }, {}],
        parameters: [
          {
            in: 'path',
            name: 'accountname',
            required: true,
            schema: { type: 'string' },
          },
          {
            in: 'query',
            name: 'limit',
            schema: { type: 'number', default: 10 },
          },
          {
            in: 'query',
            name: 'skip',
            schema: { type: 'number', default: 0 },
          },
        ],
        responses: {
          200: {
            description: 'User products',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    count: { type: 'number' },
                    product: {
                      type: 'array',
                      items: { $ref: '#/components/schemas/Product' },
                    },
                  },
                },
              },
            },
          },
          500: { description: 'Server error' },
        },
      },
    },
    '/api/product/detail/{product_id}': {
      get: {
        tags: ['Product'],
        summary: 'Get product details',
        description: 'Get details of a specific product',
        security: [{ bearerAuth: [] }, {}],
        parameters: [
          {
            in: 'path',
            name: 'product_id',
            required: true,
            schema: { type: 'string' },
          },
        ],
        responses: {
          200: {
            description: 'Product details',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    product: { $ref: '#/components/schemas/Product' },
                  },
                },
              },
            },
          },
          404: { description: 'Product not found' },
          500: { description: 'Server error' },
        },
      },
    },
    '/api/product/{product_id}': {
      put: {
        tags: ['Product'],
        summary: 'Update product',
        description: 'Update product (author only)',
        security: [{ bearerAuth: [] }],
        parameters: [
          {
            in: 'path',
            name: 'product_id',
            required: true,
            schema: { type: 'string' },
          },
        ],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  product: {
                    type: 'object',
                    properties: {
                      itemName: { type: 'string' },
                      price: { type: 'number', minimum: 1 },
                      link: { type: 'string' },
                      itemImage: { type: 'string' },
                    },
                  },
                },
              },
            },
          },
        },
        responses: {
          200: {
            description: 'Product updated successfully',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    product: { $ref: '#/components/schemas/Product' },
                  },
                },
              },
            },
          },
          400: { description: 'Validation error' },
          401: { description: 'Unauthorized' },
          403: { description: 'Forbidden - not the author' },
          404: { description: 'Product not found' },
          500: { description: 'Server error' },
        },
      },
      delete: {
        tags: ['Product'],
        summary: 'Delete product',
        description: 'Delete product (author only)',
        security: [{ bearerAuth: [] }],
        parameters: [
          {
            in: 'path',
            name: 'product_id',
            required: true,
            schema: { type: 'string' },
          },
        ],
        responses: {
          200: {
            description: 'Product deleted successfully',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    message: { type: 'string', example: '삭제되었습니다.' },
                  },
                },
              },
            },
          },
          401: { description: 'Unauthorized' },
          403: { description: 'Forbidden - not the author' },
          404: { description: 'Product not found' },
          500: { description: 'Server error' },
        },
      },
    },
  },
};

const options = {
  definition: swaggerDefinition,
  apis: [],
};

const swaggerSpec = swaggerJSDoc(options);

module.exports = swaggerSpec;
