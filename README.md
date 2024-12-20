

### **1. Admin Dashboard**
The admin dashboard is designed for administrative control and includes components and pages for managing users, roles, and other functionalities. 

- **DashSidebar**:  
  A sidebar navigation component for admins to access different sections of the dashboard.
  
- **DashboardCompartment**:  
  The main area for displaying dashboard content dynamically based on selected options in the sidebar.

- **User**:
  - **DashProfile**:  
    Displays admin profile information, including settings and preferences.
  - **DashUsers**:  
    Manages user data, including search, filtering, and administrative actions like blocking or unblocking users.
  - **UserDetails**:  
    Detailed view of a specific user, including activity logs, roles, and status.

- **Owner**:
  - **OwnerUsers**:  
    Section for managing users under a specific owner (multi-tenancy support).
  - **OwnerUserDetails**:  
    Detailed view of users belonging to a specific owner.

---

### **2. Authentication (Auth)**
Handles user authentication and account management processes.

- **Sign Up**:  
  Registration page for new users.
  
- **Password Strength**:  
  A feature that evaluates and displays the strength of a user’s password during registration.

- **Register OTP**:  
  Page to verify the OTP sent during registration.

- **Sign In**:  
  Login page for existing users.

- **Sign Out**:  
  Functionality to log users out securely.

- **OAuth**:  
  Integration with third-party services (e.g., Google, Facebook) for signing in.

- **Forgot Password**:  
  Allows users to request a password reset.

- **Validate OTP**:  
  Page for validating the OTP sent for resetting passwords.

- **Resend OTP**:  
  Functionality to resend the OTP if the initial one expires or is not received.

- **Reset OTP**:  
  Final step for setting a new password after OTP validation.

---

### **3. Email Service**
Handles all email-related functionalities in the app.

- **Sign Up**:  
  Sends a welcome email upon successful registration.

- **Sign In**:  
  Sends login notifications to users for security purposes.

- **Sign Out**:  
  Sends a logout confirmation email.

- **OTP**:  
  Sends OTPs for account verification and password resets.

- **Resend OTP**:  
  Handles requests for resending OTPs.

- **Reset Password**:  
  Sends a confirmation email once the password is reset.

---

### **4. Settings**
Configuration components for user experience and routing.

- **Splash Screen**:  
  Initial screen displayed when the app is loaded.

- **Loading Page**:  
  A spinner or loading animation displayed during data fetch or route transitions.

- **Theme Provider**:  
  Component to toggle between light and dark modes across the app.

- **Private Route**:  
  Protects routes that require user authentication.

- **Admin Route**:  
  Restricts access to admin-only sections.

- **Owner Route**:  
  Restricts access to owner-specific sections.

---

### **5. User**
Components and pages tailored for the end-user experience.

- **Header**:  
  Navigation bar with links to various pages and user options.

- **Footer**:  
  Footer section with site information, links, and copyright.

- **Home**:  
  Landing page for the application.

- **Search**:  
  A search feature for finding posts, categories, or users.

- **404**:  
  Page displayed when a route is not found.

- **About**:  
  Information about the application or team.

- **Category**:  
  Displays posts or items categorized by topics.

- **Contact**:  
  Page for users to contact the site administrators.

- **Post**:  
  Displays detailed views of blog posts or articles.

---

### **6. Functions**
Backend and frontend logic for managing users and roles.

- **User Create**:  
  Functionality to add new users to the system.

- **Get All**:  
  Fetches all users from the database with optional filters.

- **Get by ID**:  
  Fetches details of a specific user by their ID.

- **Update**:  
  Allows updates to user information, such as email or roles.

- **Delete**:  
  Removes a user from the database.

- **Block/Unblock**:  
  Enables or disables user access to the application.

- **Role**:  
  Manages user roles, such as admin, owner, or general user.
