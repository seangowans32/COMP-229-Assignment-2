import React, { useState } from 'react';

const CalCalculator = ({ onCaloriesCalculated, onFieldFocus }) => {
  const [weight, setWeight] = useState('');
  const [height, setHeight] = useState('');
  const [age, setAge] = useState('');
  const [gender, setGender] = useState('male');
  const [activityLevel, setActivityLevel] = useState(1.2);

  const calculateBMR = () => {
    if (gender === 'male') {
      return 10 * weight + 6.25 * height - 5 * age + 5;
    } else {
      return 10 * weight + 6.25 * height - 5 * age - 161;
    }
  };

  const calculateTDEE = (bmr) => {
    return bmr * activityLevel;
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    const bmr = calculateBMR();
    const tdee = calculateTDEE(bmr);
    onCaloriesCalculated({
      cut: Math.round(tdee - 500),
      maintain: Math.round(tdee),  // Rounding the maintain calories
      bulk: Math.round(tdee + 500)
    });
  };

  return (
    <div className="calorie-calculator">
      <form onSubmit={handleSubmit}>
        <div className='form-group'>
          <label>Weight (kg):</label>
          <input 
            type="number" 
            value={weight} 
            onChange={(e) => setWeight(e.target.value)} 
            onFocus={() => onFieldFocus('weight')} 
            required 
          />
        </div>
        <div className='form-group'>
          <label>Height (cm):</label>
          <input 
            type="number" 
            value={height} 
            onChange={(e) => setHeight(e.target.value)} 
            onFocus={() => onFieldFocus('height')} 
            required 
          />
        </div>
        <div className='form-group'>
          <label>Age (years):</label>
          <input 
            type="number" 
            value={age} 
            onChange={(e) => setAge(e.target.value)} 
            onFocus={() => onFieldFocus('age')} 
            required 
          />
        </div>
        <div className='form-group'>
          <label>Gender:</label>
          <select 
            value={gender} 
            onChange={(e) => setGender(e.target.value)} 
            onFocus={() => onFieldFocus('gender')}
          >
            <option value="male">Male</option>
            <option value="female">Female</option>
          </select>
        </div>
        <div className='form-group'>
          <label>Activity Level:</label>
          <select 
            value={activityLevel} 
            onChange={(e) => setActivityLevel(Number(e.target.value))} 
            onFocus={() => onFieldFocus('activityLevel')}
          >
            <option value={1.2}>Sedentary (little or no exercise)</option>
            <option value={1.375}>Lightly active (light exercise/sports 1-3 days/week)</option>
            <option value={1.55}>Moderately active (moderate exercise/sports 3-5 days/week)</option>
            <option value={1.725}>Very active (hard exercise/sports 6-7 days a week)</option>
            <option value={1.9}>Extra active (very hard exercise, physical job, or training twice a day)</option>
          </select>
        </div>
        <button className='frontend-button' type="submit">Calculate</button>
      </form>
    </div>
  );
};

export default CalCalculator;