import { initializeApp } from "firebase/app";
import { getAuth } from "firebase/auth";

// Your web app's Firebase configuration
const firebaseConfig = {
  apiKey: import.meta.env.VITE_FIREBASE_API_KEY,
  authDomain: "project-56430.firebaseapp.com",
  projectId: "project-56430",
  storageBucket: "project-56430.appspot.com",
  messagingSenderId: "570423432896",
  appId: "1:570423432896:web:b9f0940ae382fc43273f25"
};

// Initialize Firebase
export const app = initializeApp(firebaseConfig);

// Initialize Firebase Authentication
export const auth = getAuth(app);
