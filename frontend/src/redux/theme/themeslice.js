import { createSlice } from '@reduxjs/toolkit';

const initialState = {
  theme: localStorage.getItem('theme') || 'dark', // Default to dark if no preference
};

const themeSlice = createSlice({
  name: 'theme',
  initialState,
  reducers: {
    toggleTheme: (state) => {
      state.theme = state.theme === 'dark' ? 'light' : 'dark';
      localStorage.setItem('theme', state.theme); // Save user preference
    },
  },
});

export const { toggleTheme } = themeSlice.actions;
export default themeSlice.reducer;
