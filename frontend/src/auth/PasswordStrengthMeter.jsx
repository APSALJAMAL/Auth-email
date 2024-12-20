import React, { useState } from 'react';

const PasswordStrengthMeter = ({ password }) => {
  const [strength, setStrength] = useState(0);

  const calculatePasswordStrength = (password) => {
    let strengthScore = 0;

    // Check password length
    if (password.length >= 8) strengthScore += 1;

    // Check if password contains lowercase letters
    if (/[a-z]/.test(password)) strengthScore += 1;

    // Check if password contains uppercase letters
    if (/[A-Z]/.test(password)) strengthScore += 1;

    // Check if password contains numbers
    if (/[0-9]/.test(password)) strengthScore += 1;

    // Check if password contains special characters
    if (/[\W_]/.test(password)) strengthScore += 1;

    return strengthScore;
  };

  const getStrengthLabel = (score) => {
    switch (score) {
      case 0:
      case 1:
        return 'Weak';
      case 2:
        return 'Fair';
      case 3:
        return 'Good';
      case 4:
        return 'Strong';
      case 5:
        return 'Very Strong';
      default:
        return '';
    }
  };

  const strengthScore = calculatePasswordStrength(password);
  const strengthLabel = getStrengthLabel(strengthScore);

  // Optionally, you can use different colors based on strength
  const getStrengthColor = (score) => {
    switch (score) {
      case 0:
      case 1:
        return 'bg-red-500';
      case 2:
        return 'bg-yellow-500';
      case 3:
        return 'bg-blue-500';
      case 4:
        return 'bg-green-500';
      case 5:
        return 'bg-green-700';
      default:
        return 'bg-gray-300';
    }
  };

  return (
    <div className="mt-4">
      <div className="flex items-center justify-between">
        <span >Password Strength: </span>
        <span>{strengthLabel}</span>
      </div>
      <div className="relative h-2 mt-2 w-full bg-gray-200 rounded">
        <div
          className={`h-full rounded ${getStrengthColor(strengthScore)}`}
          style={{ width: `${(strengthScore / 5) * 100}%` }}
        ></div>
      </div>
    </div>
  );
};

export default PasswordStrengthMeter;
