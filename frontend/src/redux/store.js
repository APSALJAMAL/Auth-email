import { configureStore, combineReducers } from '@reduxjs/toolkit';
import userReducer from './user/userSlice.js';
import themeReducer from './theme/themeslice.js'; // Adjust the filename
import { persistReducer, persistStore } from 'redux-persist';
import storage from 'redux-persist/lib/storage';

// Combine your reducers
const rootReducer = combineReducers({
  user: userReducer,
  theme: themeReducer,
});

// Config for Redux Persist
const persistConfig = {
  key: 'root',      // Key to persist the state under
  storage,          // Use local storage
};

// Persist the rootReducer
const persistedReducer = persistReducer(persistConfig, rootReducer);

// Create the store with middleware to disable serializable check for non-serializable data
export const store = configureStore({
  reducer: persistedReducer,
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware({
      serializableCheck: {
        ignoredActions: ['persist/PERSIST'], // Ignore redux-persist actions in the serializable check
      },
    }),
});

// Persistor to handle persisting the store
export const persistor = persistStore(store);
