import React, { useState } from 'react';
import ResultBar from './ResultBar/ResultBar';
import AdditionalInfo from './AdditionalInfo/AdditionalInfo';
import CalCalculator from './CalCalculator/CalCalculator';
import FoodIntake from './FoodIntake/FoodIntake';

const BodyCalculator = () => {
  const [calories, setCalories] = useState(null);
  const [info, setInfo] = useState('');
  const [dailyCalories, setDailyCalories] = useState(0);

  const handleCaloriesCalculated = (calculatedCalories) => {
    setCalories(calculatedCalories);
  };

  const handleFocus = (field) => {
    switch (field) {
      case 'weight':
        setInfo('Weight is a crucial factor in calculating your Basal Metabolic Rate (BMR). The more you weigh, the more calories your body needs to maintain its current weight.');
        break;
      case 'height':
        setInfo('Height is used in the BMR calculation because taller individuals generally have a larger body surface area, which can affect the number of calories burned at rest.');
        break;
      case 'age':
        setInfo('Age is important in the BMR calculation because metabolic rate generally decreases with age. This means older individuals typically require fewer calories.');
        break;
      case 'gender':
        setInfo('Gender affects the BMR calculation because men and women have different body compositions. Men usually have more muscle mass, which burns more calories than fat.');
        break;
      case 'activityLevel':
        setInfo('Activity level is used to calculate your Total Daily Energy Expenditure (TDEE). The more active you are, the more calories you burn throughout the day.');
        break;
      default:
        setInfo('');
    }
  };

  const handleDailyCaloriesUpdate = (calories) => {
    setDailyCalories(calories);
  };

  return (
    <div className="body-specs">
      <ResultBar calories={calories} dailyCalories={dailyCalories} />

      <div className="flex">
        <div className='col-left'>
          <CalCalculator onCaloriesCalculated={handleCaloriesCalculated} onFieldFocus={handleFocus} />
          <AdditionalInfo info={info} />
        </div>

        <div className='col-right'>
          {calories ? (
            <FoodIntake onCaloriesUpdate={handleDailyCaloriesUpdate} />
          ) : (
            <div className="food-intake-placeholder">
              <h3>Complete Your Body Calculator First</h3>
              <p>Please fill out the calorie calculator form to get your maintain, cut, and bulk calorie goals. Once you have your goals, you'll be able to add your favorite foods and track your daily intake!</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default BodyCalculator;