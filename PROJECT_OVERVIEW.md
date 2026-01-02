# Next.js Authentication System - Complete Overview

## 🎯 Project Purpose

This is a **full-stack authentication system** built with Next.js 16, featuring user registration, login, logout, and protected routes. It uses MongoDB for data storage, JWT tokens for authentication, and Next.js middleware for route protection.

### ✨ Latest Updates (January 2, 2026)
- **User Data Fetching**: Added `/api/users/me` endpoint to retrieve current user information
- **Token Helper Utility**: Created `getDataFromToken` helper for extracting user data from JWT tokens
- **Dynamic Profile Routes**: Implemented `/profile/[id]` for individual user profile pages
- **Enhanced Profile Page**: Added "Fetch User" button to display current user ID with navigation to dynamic profile

---

## 🏗️ Architecture Overview

```mermaid
graph TB
    User[User Browser] --> Client[Client-Side Pages]
    Client --> API[API Routes]
    API --> DB[(MongoDB Atlas)]
    User --> MW[Middleware]
    MW --> Client
    
    subgraph "Client Pages"
        Login[Login Page]
        Signup[Signup Page]
        Profile[Profile Page]
        DynamicProfile[Dynamic Profile /profile/[id]]
    end
    
    subgraph "API Endpoints"
        SignupAPI[/api/users/signup]
        LoginAPI[/api/users/login]
        LogoutAPI[/api/users/logout]
        MeAPI[/api/users/me]
    end
    
    Client --> Login
    Client --> Signup
    Client --> Profile
    Client --> DynamicProfile
    
    API --> SignupAPI
    API --> LoginAPI
    API --> LogoutAPI
    API --> MeAPI
```

---

## 📁 Project Structure

```
my-app/
├── src/
│   ├── app/
│   │   ├── api/users/          # API routes
│   │   │   ├── signup/
│   │   │   ├── login/
│   │   │   ├── logout/
│   │   │   └── me/             # Get current user data
│   │   ├── login/              # Login page
│   │   ├── signup/             # Signup page
│   │   └── profile/            # Protected profile pages
│   │       ├── page.tsx        # Main profile page
│   │       └── [id]/           # Dynamic user profile
│   ├── dbConfig/               # Database connection
│   ├── models/                 # Mongoose schemas
│   ├── helpers/                # Utility functions
│   │   └── getDataFromToken.ts # JWT token decoder
│   └── middleware.ts           # Route protection
└── .env.local                  # Environment variables
```

---

## 🔑 Core Components Explained

### 1. Database Configuration

**File:** `src/dbConfig/dbConfig.ts`

```typescript
import mongoose from 'mongoose'

export async function connect() {
    try {
        mongoose.connect(process.env.MONGO_URI!)
        const connection = mongoose.connection
        
        connection.on('connected', () => {
            console.log('MongoDB connected successfully');
        });
        
        connection.on('error', (err) => {
            console.log('MongoDB connection error:', err);
            process.exit();
        });
    } catch(error) {
        console.log("something went wrong");
        console.log(error);
    }
}
```

**What it does:**
- Connects to MongoDB Atlas using the connection string from `.env.local`
- Sets up event listeners for connection success/failure
- Uses `mongoose.connect()` to establish the database connection

**Key Points:**
- `process.env.MONGO_URI!` - Reads MongoDB connection string from environment variables
- `connection.on('connected')` - Fires when database connects successfully
- `connection.on('error')` - Fires when connection fails

---

### 2. User Model (Schema)

**File:** `src/models/userModel.js`

```javascript
import mongoose from 'mongoose';

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    isVerified: { type: Boolean, default: false },
    isAdmin: { type: Boolean, default: false },
    forgotPasswordToken: String,
    forgotPasswordExpiry: Date,
    verifyToken: String,
    verifyTokenExpiry: Date,
})

const User = mongoose.models.users || mongoose.model('users', userSchema);

export default User;
```

**What it does:**
- Defines the structure of user documents in MongoDB
- Enforces data types and validation rules
- Prevents duplicate usernames and emails with `unique: true`

**Schema Fields:**
| Field | Type | Purpose |
|-------|------|---------|
| `username` | String | User's unique username |
| `email` | String | User's unique email |
| `password` | String | Hashed password (never plain text!) |
| `isVerified` | Boolean | Email verification status |
| `isAdmin` | Boolean | Admin privileges flag |
| `forgotPasswordToken` | String | Token for password reset |
| `verifyToken` | String | Token for email verification |

**Important Pattern:**
```javascript
mongoose.models.users || mongoose.model('users', userSchema)
```
- Checks if model already exists (prevents re-compilation errors in development)
- Creates new model only if it doesn't exist

---

### 3. Signup API Route

**File:** `src/app/api/users/signup/route.ts`

```typescript
import { connect } from "@/dbConfig/dbConfig";
import User from "@models/userModel";
import bcrypt from "bcryptjs";
import { NextResponse, NextRequest } from "next/server";

connect(); // Connect to database

export async function POST(request: NextRequest) {
    try {
        const reqBody = await request.json();
        const { username, email, password } = reqBody;

        // Check if user already exists
        const user = await User.findOne({ email })
        if (user) {
            return NextResponse.json({ error: "User already exists" }, { status: 400 });
        }
        
        // Hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Create new user
        const newUser = new User({
            username,
            email,
            password: hashedPassword,
        });

        const savedUser = await newUser.save();
        return NextResponse.json({ message: "User created successfully", user: savedUser }, { status: 201 });
    } catch (error: any) {
        return NextResponse.json({ error: error.message }, { status: 500 });
    }
}
```

**Flow Breakdown:**

1. **Receive Data** → `request.json()` extracts username, email, password
2. **Check Duplicates** → `User.findOne({ email })` checks if email exists
3. **Hash Password** → `bcrypt.hash()` encrypts password (security!)
4. **Save User** → `newUser.save()` stores in MongoDB
5. **Return Response** → Send success/error message

**Security Highlights:**
- ✅ **Never stores plain text passwords** - uses bcrypt hashing
- ✅ **Salt rounds = 10** - Makes password cracking extremely difficult
- ✅ **Duplicate prevention** - Checks existing users before creating

**What is Password Hashing?**
```typescript
const salt = await bcrypt.genSalt(10);
const hashedPassword = await bcrypt.hash(password, salt);
```
- **Plain password:** `"mypassword123"`
- **Hashed password:** `"$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"`
- Even if database is compromised, attackers can't read actual passwords!

---

### 4. Login API Route

**File:** `src/app/api/users/login/route.ts`

```typescript
import { connect } from "@/dbConfig/dbConfig";
import User from "@models/userModel";
import bcrypt from "bcryptjs";
import { NextResponse, NextRequest } from "next/server";
import jwt from "jsonwebtoken";

connect();

export async function POST(request: NextRequest){
    try {
        const reqBody = await request.json();
        const { email, password } = reqBody;

        // Check if user exists
        const user = await User.findOne({ email });
        if (!user) {
            return NextResponse.json({ error: "User does not exist" }, { status: 400 });
        }

        // Check if password is correct
        const isPasswordCorrect = await bcrypt.compare(password, user.password);
        if (!isPasswordCorrect) {
            return NextResponse.json({ error: "Invalid password" }, { status: 400 });
        }

        // Create token data
        const tokenData = {
            id: user._id,
            username: user.username,
            email: user.email,
        }

        // Create JWT token
        const token = jwt.sign(tokenData, process.env.TOKEN_SECRET!, {
            expiresIn: "1d",
        });

        // Set token in cookie
        const response = NextResponse.json({
            message: "Login successful",
            success: true,
        });
        response.cookies.set("token", token, {
            httpOnly: true,
        });
        return response;
    } catch (error:any) {
         return NextResponse.json({error: error.message}, {status: 500})
    }
}
```

**Flow Breakdown:**

1. **Receive Credentials** → Extract email & password
2. **Find User** → `User.findOne({ email })` searches database
3. **Verify Password** → `bcrypt.compare()` checks if password matches hash
4. **Create JWT Token** → `jwt.sign()` generates authentication token
5. **Set Cookie** → Store token in httpOnly cookie (secure!)
6. **Return Success** → Send login confirmation

**JWT Token Explained:**

```typescript
const tokenData = {
    id: user._id,        // User's database ID
    username: user.username,
    email: user.email,
}

const token = jwt.sign(tokenData, process.env.TOKEN_SECRET!, {
    expiresIn: "1d",     // Token expires in 1 day
});
```

**What is JWT?**
- **J**SON **W**eb **T**oken - A secure way to transmit user information
- Contains user data (id, username, email) in encrypted format
- Signed with `TOKEN_SECRET` to prevent tampering
- Expires after 1 day for security

**Example JWT Token:**
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY3YTEyMzQ1Njc4OWFiY2RlZiIsInVzZXJuYW1lIjoibWVzc2kiLCJlbWFpbCI6Im1lc3NpQGdtYWlsLmNvbSIsImlhdCI6MTcwNDEyMzQ1NiwiZXhwIjoxNzA0MjA5ODU2fQ.abc123xyz789signature
```
- **Part 1 (Header):** Algorithm & token type
- **Part 2 (Payload):** User data (id, username, email)
- **Part 3 (Signature):** Verification signature

**Cookie Security:**
```typescript
response.cookies.set("token", token, {
    httpOnly: true,  // ← JavaScript cannot access this cookie (prevents XSS attacks)
});
```

> **Why `httpOnly: true`?**
> - Prevents malicious JavaScript from stealing the token
> - Cookie is only sent with HTTP requests, not accessible via `document.cookie`
> - Protects against Cross-Site Scripting (XSS) attacks

---

### 5. Logout API Route

**File:** `src/app/api/users/logout/route.ts`

```typescript
import { NextResponse, NextRequest } from "next/server";

export async function GET(){
    try {
        const response = NextResponse.json({
            message: "Logout successful",
            success: true
        }, {status: 200})
        
        response.cookies.set("token", "", {
            httpOnly: true,
            secure: true, 
        })
        return response
    } catch (error: any) {
        return NextResponse.json({error: error.message}, {status: 500})
    }
}
```

**What it does:**
- Clears the authentication token by setting it to an empty string
- User is now logged out (no valid token = no access to protected routes)

**Simple but Effective:**
```typescript
response.cookies.set("token", "", { ... })
```
- Sets token to empty string → effectively deletes it
- Next request won't have a valid token → middleware redirects to login

---

---

### 6. Get Current User Data Helper

**File:** `src/helpers/getDataFromToken.ts`

```typescript
import { NextRequest } from "next/server";
import jwt from "jsonwebtoken";

export const getDataFromToken = (request: NextRequest) => {
    try {
        const token = request.cookies.get("token")?.value || "";
        const decodedToken: any = jwt.verify(token, process.env.TOKEN_SECRET!);
        return decodedToken.id;
    } catch (error) {
        console.log(error);
        return null;
    }
};
```

**What it does:**
- Extracts the JWT token from the request cookies
- Decodes and verifies the token using the `TOKEN_SECRET`
- Returns the user ID from the decoded token
- Returns `null` if token is invalid or missing

**Key Features:**
```typescript
const token = request.cookies.get("token")?.value || "";
```
- Gets token from httpOnly cookie
- Uses optional chaining (`?.`) to safely access the value
- Defaults to empty string if no token exists

```typescript
const decodedToken: any = jwt.verify(token, process.env.TOKEN_SECRET!);
```
- **`jwt.verify()`** - Verifies token signature and expiration
- Throws error if token is invalid or expired
- Returns decoded payload containing user data

**Why this helper is useful:**
- **Reusability** - Can be used in any API route that needs user information
- **Security** - Centralized token verification logic
- **Clean Code** - Avoids repeating token extraction code

---

### 7. Get Current User API Route

**File:** `src/app/api/users/me/route.ts`

```typescript
import { getDataFromToken } from "@/helpers/getDataFromToken";
import { NextRequest, NextResponse } from "next/server";
import User from "@/models/userModel"
import {connect} from "@/dbConfig/dbConfig"

connect();

export async function GET(request: NextRequest) {
    try {
        const userId = await getDataFromToken(request);
        const user = await User.findOne({ _id: userId }).select("-password");
        return NextResponse.json({data:user,message:"User found"});
    } catch (error:any) {
        console.log(error);
        return NextResponse.json({ error: error.message }, { status: 401 });
    }
}
```

**What it does:**
- Protected endpoint that returns the currently logged-in user's data
- Uses `getDataFromToken` helper to extract user ID from JWT
- Fetches user from database (excluding password)
- Returns user data in JSON format

**Flow Breakdown:**

1. **Extract User ID** → `getDataFromToken(request)` gets user ID from token
2. **Query Database** → `User.findOne({ _id: userId })` finds the user
3. **Exclude Password** → `.select("-password")` removes password from response
4. **Return Data** → Send user data to client

**Security Highlights:**
```typescript
.select("-password")
```
- **Critical security feature** - Never send password hash to client!
- MongoDB query modifier that excludes the password field
- Even though password is hashed, it should never be exposed

**Example Response:**
```json
{
    "data": {
        "_id": "67a1234567abcdef",
        "username": "johndoe",
        "email": "john@example.com",
        "isVerified": false,
        "isAdmin": false
    },
    "message": "User found"
}
```

**Error Handling:**
- Returns **401 Unauthorized** if token is invalid or user not found
- Catches any errors during token verification or database query

---

### 8. Middleware (Route Protection) ⭐

**File:** `src/middleware.ts`

```typescript
import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'

export function middleware(request: NextRequest) {
  const path = request.nextUrl.pathname

  const isPublicPath = path === '/login' || path === '/signup' || path === '/verifyemail'

  const token = request.cookies.get('token')?.value || ''

  if(isPublicPath && token) {
    return NextResponse.redirect(new URL('/profile', request.nextUrl))
  }

  if (!isPublicPath && !token) {
    return NextResponse.redirect(new URL('/login', request.nextUrl))
  }
}

export const config = {
  matcher: [ 
    '/',
    '/profile/:path*',
    '/login',
    '/signup',
  ]
}
```

**How Middleware Works:**

```mermaid
graph TD
    A[User Requests Page] --> B{Get Current Path}
    B --> C{Is Public Path?}
    C -->|Yes| D{Has Token?}
    C -->|No| E{Has Token?}
    D -->|Yes| F[Redirect to /profile]
    D -->|No| G[Allow Access]
    E -->|Yes| H[Allow Access]
    E -->|No| I[Redirect to /login]
```

**Code Breakdown:**

```typescript
const path = request.nextUrl.pathname
// Extracts the path from the URL
// Example: http://localhost:3000/profile/123 → path = "/profile/123"

const isPublicPath = path === '/login' || path === '/signup' || path === '/verifyemail'
// Defines which pages anyone can access without authentication

const token = request.cookies.get('token')?.value || ''
// Gets the JWT token from cookies
// If no token exists, defaults to empty string
```

**Protection Logic:**

| Scenario | Path Type | Has Token? | Action |
|----------|-----------|------------|--------|
| Logged-in user visits login | Public | ✅ Yes | Redirect to `/profile` |
| Guest visits login | Public | ❌ No | Allow access |
| Logged-in user visits profile | Protected | ✅ Yes | Allow access |
| Guest visits profile | Protected | ❌ No | Redirect to `/login` |

**Matcher Configuration:**
```typescript
matcher: [
    '/',
    '/profile/:path*',  // ← Protects ALL /profile routes
    '/login',
    '/signup',
]
```

**What is `/profile/:path*`?**
- `:path*` is a **wildcard** that matches any path segments
- Protects:
  - `/profile` (main profile page)
  - `/profile/123` (dynamic user profiles)
  - `/profile/settings` (settings page)
  - `/profile/anything/nested/deeply` (all nested routes)

**Why Middleware is Powerful:**
- Runs **BEFORE** the page loads
- Centralized authentication logic (no need to check auth on every page)
- Automatic redirects (seamless user experience)

---

### 9. Login Page (Client-Side)

**File:** `src/app/login/page.tsx`

```typescript
"use client"
import React, { useEffect } from "react";
import { useRouter } from "next/navigation";
import axios from "axios";
import { toast } from "react-hot-toast";

export default function LoginPage(){
    const [user, setUser] = React.useState({
        email: "",
        password: "",
    })
    const router = useRouter()
    const [buttonDisabled, setButtonDisabled] = React.useState(false);
    const [loading, setLoading] = React.useState(false);

    const onLogin = async () => {
        try {
            setLoading(true);
            const response = await axios.post("/api/users/login", user);
            console.log("Login success", response.data);
            toast.success("Login success");
            router.push("/profile");
        } catch (error:any) {
            console.log("Login failed", error.message);
            toast.error(error.message);
        } finally {
            setLoading(false);
        }
    }

    useEffect(() => {
        if(user.email.length > 0 && user.password.length > 0) {
            setButtonDisabled(false);
        } else {
            setButtonDisabled(true);
        }
    }, [user]);

    return(
        <div className="flex flex-col justify-center items-center w-full h-screen bg-black gap-4">
            <h1 className="h1 text-2xl text-center text-white">login</h1>
            <input type="email" 
                placeholder="email" 
                value={user.email} 
                onChange={(e) => setUser({...user, email: e.target.value})} 
            />
            <input type="password"
                placeholder="password" 
                value={user.password} 
                onChange={(e) => setUser({...user, password: e.target.value})} 
            />
            <button onClick={onLogin}>Login</button>
        </div>
    )
}
```

**Key Features:**

1. **`"use client"` Directive**
   ```typescript
   "use client"
   ```
   - Required for React hooks (`useState`, `useEffect`, `useRouter`)
   - Enables client-side interactivity (button clicks, form inputs)
   - Without this, Next.js treats it as a server component (no interactivity)

2. **State Management:**
   ```typescript
   const [user, setUser] = React.useState({ email: "", password: "" })
   ```
   - Stores form input values in component state
   - Updates in real-time as user types

3. **Form Validation:**
   ```typescript
   useEffect(() => {
       if(user.email.length > 0 && user.password.length > 0) {
           setButtonDisabled(false);
       } else {
           setButtonDisabled(true);
       }
   }, [user]);
   ```
   - Runs whenever `user` state changes
   - Disables login button if fields are empty
   - Prevents submitting incomplete forms

4. **API Call:**
   ```typescript
   const response = await axios.post("/api/users/login", user);
   ```
   - Sends email & password to `/api/users/login`
   - Server validates credentials and returns JWT token
   - Token is automatically stored in httpOnly cookie

5. **Navigation:**
   ```typescript
   router.push("/profile");
   ```
   - Redirects to profile page after successful login
   - Uses Next.js App Router navigation

6. **Loading State:**
   ```typescript
   setLoading(true);  // Show loading indicator
   // ... API call ...
   setLoading(false); // Hide loading indicator
   ```
   - Provides user feedback during login process

---

### 10. Profile Page (Enhanced)

**File:** `src/app/profile/page.tsx`

```typescript
"use client"
import { NextResponse } from "next/server";
import { useRouter } from "next/navigation";
import axios from "axios";
import { toast } from "react-hot-toast";
import { useState , useEffect} from "react";
import Link from "next/link";

export default function ProfilePage() {
    const router = useRouter()
    const [data, setData] = useState("nothing")
    
    const handleLogout = async () => {
        try {
            axios.get("/api/users/logout")
            toast.success("Logout successful")
            router.push("/login")
        } catch (error: any) {
            return toast.error(error.response.data.message)
        }
    }
    
    const fetchUser = async () => {
        try {
            const response = await axios.get("/api/users/me")
            setData(response.data.data._id)
            console.log(response.data.data._id)
        } catch (error: any) {
            console.log(error)
        }
    }

    return (
        <div className="flex flex-col justify-center items-center w-full h-screen bg-black gap-4">
            <h1 className="h1 text-2xl text-center text-white">profile page</h1>
            <h2>{data==="nothing"?"nothing":
                <Link className="text-white bg-blue-500 p-2 rounded hover:bg-blue-600 transition"
                href={`/profile/${data}`}>
                {data}
                </Link>}
            </h2>
            <hr/>

            <button onClick={handleLogout} className="bg-red-500 text-white p-2 rounded hover:bg-red-600 transition">
                Logout
            </button>

            <button onClick={fetchUser} className="bg-blue-500 text-white p-2 rounded hover:bg-blue-600 transition">
                Fetch User
            </button>

        </div>
    )
}
```

**New Features:**

1. **User Data State:**
   ```typescript
   const [data, setData] = useState("nothing")
   ```
   - Stores the current user's ID
   - Initially set to "nothing" before fetching

2. **Fetch User Function:**
   ```typescript
   const fetchUser = async () => {
       const response = await axios.get("/api/users/me")
       setData(response.data.data._id)
   }
   ```
   - Calls the new `/api/users/me` endpoint
   - Extracts user ID from response
   - Updates component state with user ID

3. **Dynamic Link to User Profile:**
   ```typescript
   <Link href={`/profile/${data}`}>
       {data}
   </Link>
   ```
   - Creates a clickable link to `/profile/[id]`
   - Only displays when user ID is fetched
   - Shows "nothing" before fetching

4. **Fetch User Button:**
   ```typescript
   <button onClick={fetchUser}>Fetch User</button>
   ```
   - Triggers user data retrieval
   - Demonstrates interaction with the `/api/users/me` endpoint

**User Flow:**
1. User visits `/profile` (must be logged in)
2. Page displays "nothing" initially
3. User clicks "Fetch User" button
4. App calls `/api/users/me` with JWT token
5. Server returns user data
6. User ID displays as clickable link
7. Clicking link navigates to `/profile/[userId]`

---

### 11. Dynamic User Profile Page

**File:** `src/app/profile/[id]/page.tsx`

```typescript
interface UserProfileParams {
    id: string;
}

type PageProps = {
    params: Promise<UserProfileParams>;
};

export default async function UserProfile({ params }: PageProps) {
    const { id } = await params; 
    
    return (
        <div className="flex flex-col justify-center items-center w-full h-screen bg-black gap-4">
            <h1 className="h1 text-2xl text-center text-white">profile page</h1>
            <p className="text-white">User ID: {id}</p>
        </div>
    );
}
```

**What it does:**
- Creates a dynamic route at `/profile/[id]`
- Displays individual user profile based on URL parameter
- **Server Component** (no "use client" directive)

**Key Concepts:**

1. **Dynamic Route Segment:**
   ```typescript
   [id]
   ```
   - The folder name `[id]` creates a dynamic route
   - Matches any path like `/profile/123`, `/profile/abc`, etc.
   - The value becomes available in the `params` object

2. **Async Params (Next.js 16):**
   ```typescript
   params: Promise<UserProfileParams>
   const { id } = await params;
   ```
   - In Next.js 16, `params` is a Promise that must be awaited
   - This is a breaking change from Next.js 15
   - Ensures params are ready before rendering

3. **TypeScript Typing:**
   ```typescript
   interface UserProfileParams {
       id: string;
   }
   ```
   - Provides type safety for dynamic route parameters
   - Ensures `id` is always a string

**Example URLs:**
- `/profile/67a1234567abcdef` → Shows User ID: 67a1234567abcdef
- `/profile/anything` → Shows User ID: anything

**Future Enhancements:**
- Fetch full user data using the ID
- Display username, email, and other non-sensitive information
- Add edit profile functionality (if viewing own profile)
- Show different content for admins

---

## 🔐 Environment Variables

**File:** `.env.local` (in `my-app/` directory)

```
MONGO_URI=mongodb+srv://username:password@cluster.mongodb.net/
TOKEN_SECRET=qwertyuiop
```

**Variables Explained:**

| Variable | Purpose | Security Level |
|----------|---------|----------------|
| `MONGO_URI` | MongoDB connection string | 🔒 Server-only |
| `TOKEN_SECRET` | JWT signing key | 🔒 Server-only |

> **CRITICAL: Never use `NEXT_PUBLIC_` prefix for secrets!**
> 
> ❌ **WRONG:** `NEXT_PUBLIC_TOKEN_SECRET=abc123`
> - Exposes secret to browser (anyone can see it!)
> - Attackers can create fake JWT tokens
> - Major security vulnerability
> 
> ✅ **CORRECT:** `TOKEN_SECRET=abc123`
> - Only accessible on server
> - Browser cannot see this value
> - Secure authentication

**Why Environment Variables?**
- Keeps sensitive data out of code
- Different values for development/production
- Easy to change without modifying code
- Not committed to Git (in `.gitignore`)

---

## 🔄 Complete Authentication Flow

### Signup Flow

```mermaid
sequenceDiagram
    participant U as User
    participant C as Client (Signup Page)
    participant A as API (/api/users/signup)
    participant DB as MongoDB

    U->>C: Enters username, email, password
    C->>A: POST request with user data
    A->>DB: Check if email exists
    DB-->>A: User not found
    A->>A: Hash password with bcrypt
    A->>DB: Save new user
    DB-->>A: User saved successfully
    A-->>C: 201 Created
    C->>C: Redirect to /login
```

**Step-by-Step:**
1. User fills signup form
2. Client sends data to `/api/users/signup`
3. Server checks if email already exists
4. Server hashes password with bcrypt
5. Server saves user to MongoDB
6. Server responds with success
7. Client redirects to login page

---

### Login Flow

```mermaid
sequenceDiagram
    participant U as User
    participant C as Client (Login Page)
    participant A as API (/api/users/login)
    participant DB as MongoDB

    U->>C: Enters email, password
    C->>A: POST request
    A->>DB: Find user by email
    DB-->>A: User found
    A->>A: Compare password with bcrypt
    A->>A: Generate JWT token
    A->>C: Set httpOnly cookie with token
    C->>C: Redirect to /profile
```

**Step-by-Step:**
1. User enters credentials
2. Client sends to `/api/users/login`
3. Server finds user in database
4. Server verifies password with bcrypt
5. Server creates JWT token
6. Server sets token in httpOnly cookie
7. Client redirects to profile page

---

### Protected Route Access

```mermaid
sequenceDiagram
    participant U as User
    participant M as Middleware
    participant P as Profile Page

    U->>M: Request /profile
    M->>M: Check for token cookie
    alt Has valid token
        M->>P: Allow access
        P-->>U: Show profile page
    else No token
        M-->>U: Redirect to /login
    end
```

**Step-by-Step:**
1. User tries to access `/profile`
2. Middleware intercepts request
3. Middleware checks for token cookie
4. **If token exists:** Allow access to profile
5. **If no token:** Redirect to login page

---

### Logout Flow

```mermaid
sequenceDiagram
    participant U as User
    participant C as Client (Profile Page)
    participant A as API (/api/users/logout)

    U->>C: Clicks "Logout" button
    C->>A: GET /api/users/logout
    A->>A: Clear token cookie
    A-->>C: Success response
    C->>C: Redirect to /login
```

**Step-by-Step:**
1. User clicks logout button
2. Client calls `/api/users/logout`
3. Server clears token cookie
4. Client redirects to login page
5. User is now logged out

---

### Get User Data Flow (New)

```mermaid
sequenceDiagram
    participant U as User
    participant C as Client (Profile Page)
    participant A as API (/api/users/me)
    participant H as Helper (getDataFromToken)
    participant DB as MongoDB

    U->>C: Clicks "Fetch User" button
    C->>A: GET /api/users/me (with token cookie)
    A->>H: Extract user ID from token
    H->>H: Verify JWT signature
    H-->>A: Return user ID
    A->>DB: Find user by ID
    DB-->>A: User data (excluding password)
    A-->>C: JSON response with user data
    C->>C: Update state with user ID
    C->>C: Display clickable link to /profile/[id]
```

**Step-by-Step:**
1. User clicks "Fetch User" button on profile page
2. Client sends GET request to `/api/users/me` with JWT token in cookie
3. Server extracts and verifies JWT token using `getDataFromToken` helper
4. Helper decodes token and returns user ID
5. Server queries MongoDB for user data (excluding password field)
6. Server returns user data in JSON format
7. Client updates state with user ID
8. User ID displays as clickable link to dynamic profile page

---

## 🛡️ Security Features

| Feature | Implementation | Protection Against |
|---------|----------------|---------------------|
| **Password Hashing** | bcrypt with salt rounds | Password database leaks |
| **JWT Tokens** | Signed with secret key | Token tampering |
| **httpOnly Cookies** | JavaScript cannot access | XSS attacks |
| **Middleware Protection** | Route-level authentication | Unauthorized access |
| **Environment Variables** | Server-side secrets | Credential exposure |
| **Token Expiration** | 1 day expiry | Stolen token abuse |
| **Password Exclusion** | `.select("-password")` in queries | Sensitive data exposure |

### Security Deep Dive

#### 1. Password Hashing with bcrypt

**Why we don't store plain passwords:**
```
❌ BAD: password = "mypassword123"
✅ GOOD: password = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
```

**How bcrypt works:**
```typescript
const salt = await bcrypt.genSalt(10);  // Generate random salt
const hashedPassword = await bcrypt.hash(password, salt);  // Hash password
```

- **Salt:** Random data added to password before hashing
- **Rounds (10):** Number of times hashing algorithm runs (higher = more secure, slower)
- **Result:** Even identical passwords have different hashes

**Example:**
```
Password: "hello123"
Hash 1:   "$2a$10$abc...xyz"
Hash 2:   "$2a$10$def...uvw"  (different salt = different hash!)
```

#### 2. JWT Token Security

**Token Structure:**
```
Header.Payload.Signature
```

**Signing Process:**
```typescript
jwt.sign(tokenData, process.env.TOKEN_SECRET!, { expiresIn: "1d" })
```

- **Header:** Algorithm (HS256)
- **Payload:** User data (id, username, email)
- **Signature:** Encrypted with `TOKEN_SECRET`

**Why it's secure:**
- Tampering changes signature → token becomes invalid
- Only server knows `TOKEN_SECRET` → only server can create valid tokens
- Expiration prevents old tokens from working forever

#### 3. httpOnly Cookies

**Without httpOnly:**
```javascript
// Attacker can steal token!
const token = document.cookie;
sendToAttacker(token);
```

**With httpOnly:**
```javascript
// Returns empty string - token is protected!
const token = document.cookie;  // ""
```

- Browser automatically sends cookie with requests
- JavaScript cannot read the cookie
- Protects against XSS (Cross-Site Scripting) attacks

---

## 📊 Project Dependencies

```json
{
  "dependencies": {
    "next": "^16.1.1",           // React framework with server components
    "react": "^19.0.0",          // UI library
    "mongoose": "^8.x",          // MongoDB object modeling
    "bcryptjs": "^2.x",          // Password hashing
    "jsonwebtoken": "^9.x",      // JWT creation/verification
    "axios": "^1.x",             // HTTP client for API calls
    "react-hot-toast": "^2.x"    // Toast notifications
  },
  "devDependencies": {
    "@types/jsonwebtoken": "^9.x"  // TypeScript types for JWT
  }
}
```

**Why each dependency?**

- **Next.js:** Full-stack React framework with routing, API routes, middleware
- **React:** UI components and state management
- **Mongoose:** Easy MongoDB integration with schemas and validation
- **bcryptjs:** Industry-standard password hashing
- **jsonwebtoken:** Create and verify JWT tokens
- **axios:** Make HTTP requests from client to API
- **react-hot-toast:** User-friendly notifications

---

## 🎓 Key Concepts Summary

### 1. Authentication vs Authorization

- **Authentication** = "Who are you?" (Login/Signup)
  - Verifying user identity
  - Checking credentials (email + password)
  - Creating session (JWT token)

- **Authorization** = "What can you access?" (Middleware)
  - Checking permissions
  - Protecting routes
  - Allowing/denying access

### 2. JWT (JSON Web Token)

**What it is:**
- Encrypted string containing user data
- Self-contained (no database lookup needed)
- Stateless authentication

**Structure:**
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9    ← Header
.
eyJpZCI6IjEyMyIsInVzZXJuYW1lIjoiam9obiJ9  ← Payload (user data)
.
SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c  ← Signature
```

**Benefits:**
- No server-side session storage needed
- Can be verified without database
- Works across multiple servers (scalable)

### 3. Middleware in Next.js

**What it does:**
- Runs **BEFORE** page loads
- Intercepts every request
- Can redirect, rewrite, or allow access

**When it runs:**
```
User Request → Middleware → Page/API Route
```

**Use cases:**
- Authentication checks
- Logging
- Redirects
- Header modifications

### 4. Password Security

**Never do this:**
```typescript
❌ password: "mypassword123"  // Plain text - VERY BAD!
```

**Always do this:**
```typescript
✅ password: "$2a$10$..."  // Hashed with bcrypt - SECURE!
```

**Why hashing matters:**
- Database breach doesn't expose passwords
- Rainbow table attacks don't work (salt is unique)
- Brute force attacks are extremely slow (bcrypt is designed to be slow)

### 5. Client vs Server Components

**Server Components (default):**
```typescript
// No "use client" directive
export default function Page() {
    // Runs on server
    // No hooks, no interactivity
    // Better performance
}
```

**Client Components:**
```typescript
"use client"  // ← Required!
export default function Page() {
    // Runs in browser
    // Can use hooks (useState, useEffect)
    // Interactive (onClick, onChange)
}
```

**When to use client components:**
- Need React hooks
- Need event handlers (onClick, onChange)
- Need browser APIs (localStorage, window)

---

## 🚀 How to Test the Application

### 1. Start the Development Server

```bash
cd my-app
npm run dev
```

Server runs at: `http://localhost:3000`

---

### 2. Test Signup Flow

1. Visit `http://localhost:3000/signup`
2. Enter:
   - Username: `testuser`
   - Email: `test@example.com`
   - Password: `password123`
3. Click "Sign Up"
4. Should redirect to `/login`
5. Check MongoDB - user should be created with hashed password

---

### 3. Test Login Flow

1. Visit `http://localhost:3000/login`
2. Enter:
   - Email: `test@example.com`
   - Password: `password123`
3. Click "Login"
4. Should redirect to `/profile`
5. Check browser cookies - should see `token` cookie

---

### 4. Test Protected Routes

**Scenario 1: Access profile without login**
1. Clear cookies (logout if logged in)
2. Try to visit `http://localhost:3000/profile`
3. Should automatically redirect to `/login`

**Scenario 2: Access profile with login**
1. Login first
2. Visit `http://localhost:3000/profile`
3. Should see profile page

**Scenario 3: Access login while logged in**
1. Login first
2. Try to visit `http://localhost:3000/login`
3. Should redirect to `/profile`

---

### 5. Test Logout

1. Login to your account
2. Visit `/profile`
3. Click "Logout" button
4. Should redirect to `/login`
5. Check cookies - `token` should be cleared
6. Try accessing `/profile` - should redirect to `/login`

---

### 6. Test Middleware Protection

**Test `/profile/:path*` wildcard:**
1. Logout (clear cookies)
2. Try accessing:
   - `http://localhost:3000/profile` → Redirects to `/login`
   - `http://localhost:3000/profile/123` → Redirects to `/login`
   - `http://localhost:3000/profile/settings` → Redirects to `/login`
3. All should redirect because middleware protects `/profile/:path*`

---

### 7. Test Fetch User Data (New)

1. Login to your account
2. Visit `/profile`
3. Click "Fetch User" button
4. Should display your user ID
5. User ID should be shown as a clickable blue link
6. Click the user ID link
7. Should navigate to `/profile/[your-user-id]`
8. Dynamic profile page should display "User ID: [your-user-id]"

**Testing the API directly:**
- Open browser DevTools → Network tab
- Click "Fetch User" button
- Inspect the request to `/api/users/me`
- Response should contain user data (without password field)

---

### 8. Test Dynamic Routes

1. Login first
2. Visit `/profile/123abc` in browser
3. Should show "User ID: 123abc"
4. Try `/profile/test-user` → Shows "User ID: test-user"
5. Dynamic `[id]` parameter is captured from URL

---

## 🎯 What You've Built

✅ **User Registration** with password hashing  
✅ **User Login** with JWT authentication  
✅ **Protected Routes** with middleware  
✅ **Logout Functionality** with cookie clearing  
✅ **User Data Fetching** with `/api/users/me` endpoint *(New)*  
✅ **Dynamic Profile Routes** with `/profile/[id]` *(New)*  
✅ **JWT Token Helper** with `getDataFromToken` utility *(New)*  
✅ **Database Integration** with MongoDB Atlas  
✅ **Type Safety** with TypeScript  
✅ **Modern UI** with React and Tailwind CSS  
✅ **Security Best Practices** (httpOnly cookies, bcrypt, JWT, password exclusion)  
✅ **Scalable Architecture** (API routes, middleware, client/server components, helper utilities)  


---

## 🔧 Common Issues & Solutions

### Issue 1: "Cannot find module '@/dbConfig/dbConfig'"

**Solution:** Check `tsconfig.json` has path aliases:
```json
{
  "compilerOptions": {
    "paths": {
      "@/*": ["./src/*"],
      "@models/*": ["./src/models/*"]
    }
  }
}
```

---

### Issue 2: "500 Internal Server Error" on login

**Cause:** `TOKEN_SECRET` environment variable not set

**Solution:**
1. Check `.env.local` exists in `my-app/` directory
2. Ensure it contains: `TOKEN_SECRET=your-secret-key`
3. Restart dev server (environment variables load on startup)

---

### Issue 3: MongoDB connection fails

**Cause:** Invalid `MONGO_URI` or network issue

**Solution:**
1. Check `.env.local` has correct MongoDB connection string
2. Ensure MongoDB Atlas allows connections from your IP
3. Check MongoDB Atlas user has correct permissions

---

### Issue 4: TypeScript error on `jsonwebtoken`

**Cause:** Missing type definitions

**Solution:**
```bash
npm install --save-dev @types/jsonwebtoken
```

---

## 📚 Next Steps & Improvements

### Features to Add:

1. **Email Verification**
   - Send verification email on signup
   - Use `verifyToken` and `verifyTokenExpiry` fields
   - Implement `/api/users/verifyemail` route

2. **Password Reset**
   - "Forgot Password" link on login page
   - Use `forgotPasswordToken` and `forgotPasswordExpiry`
   - Implement `/api/users/resetpassword` route

3. **User Profile Management**
   - Edit username, email
   - Change password
   - Upload profile picture

4. **Admin Dashboard**
   - Use `isAdmin` field
   - Admin-only routes
   - User management

5. **Refresh Tokens**
   - Long-lived refresh tokens
   - Short-lived access tokens
   - Better security

6. **OAuth Integration**
   - Google login
   - GitHub login
   - Social authentication

---

## 🎓 Learning Resources

### Concepts Covered:
- ✅ Next.js App Router
- ✅ API Routes
- ✅ Middleware
- ✅ Dynamic Routes *(New - `/profile/[id]`)*
- ✅ MongoDB with Mongoose
- ✅ JWT Authentication
- ✅ JWT Token Decoding *(New - `getDataFromToken` helper)*
- ✅ Password Hashing
- ✅ TypeScript
- ✅ React Hooks
- ✅ Client vs Server Components

### Further Reading:
- [Next.js Documentation](https://nextjs.org/docs)
- [Next.js Dynamic Routes](https://nextjs.org/docs/app/building-your-application/routing/dynamic-routes)
- [JWT.io](https://jwt.io) - JWT debugger
- [Mongoose Docs](https://mongoosejs.com/docs/)
- [bcrypt Explained](https://en.wikipedia.org/wiki/Bcrypt)

---

## 🎉 Conclusion

You've built a **production-ready authentication system** that follows industry best practices for security and scalability!

**Key Achievements:**
- 🔐 Secure password storage with bcrypt
- 🎫 Stateless authentication with JWT
- 🛡️ Route protection with middleware
- 👤 User data fetching with protected endpoints *(New)*
- 🔀 Dynamic routing for user profiles *(New)*
- 🛠️ Reusable helper utilities *(New)*
- 📦 Clean architecture with separation of concerns
- 🚀 Scalable design ready for production

This project demonstrates understanding of:
- Full-stack development
- Security principles
- Database design
- API development
- Modern React patterns
- Dynamic routing in Next.js *(New)*
- Helper utility patterns *(New)*

**Great work!** 🎊

---

## 📅 Change Log

### January 2, 2026 - User Data Features
- ✨ **Added** `/api/users/me` endpoint for fetching current user data
- ✨ **Created** `getDataFromToken` helper utility for JWT token extraction
- ✨ **Implemented** dynamic profile routes at `/profile/[id]`
- ✨ **Enhanced** profile page with "Fetch User" functionality
- 🔒 **Security** - Ensured password field exclusion in user data responses
- 📝 **Documentation** - Updated PROJECT_OVERVIEW.md with all new features

