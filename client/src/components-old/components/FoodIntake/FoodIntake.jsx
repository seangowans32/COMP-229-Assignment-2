import React, { useState } from 'react';

function FoodIntake({ onCaloriesUpdate }) {
    const [food, setFood] = useState('');
    const [calories, setCalories] = useState('');
    const [favorites, setFavorites] = useState([]);
    const [dailyCalories, setDailyCalories] = useState(0);

    const addFood = (e) => {
        e.preventDefault();
        
        // Check for duplicates
        const foodName = food.trim().toLowerCase();
        const existingFood = favorites.find(fav => fav.name.toLowerCase() === foodName);
        
        if (existingFood) {
            alert('This food is already in your favorites!');
            return;
        }
        
        const newFood = {
            id: Date.now(),
            name: food.trim(),
            calories: parseInt(calories)
        };
        
        setFavorites([...favorites, newFood]);
        setFood('');
        setCalories('');
    };

    const addCalories = (foodItem) => {
        const newDailyCalories = dailyCalories + foodItem.calories;
        setDailyCalories(newDailyCalories);
        onCaloriesUpdate(newDailyCalories);
    };

    const subtractCalories = (foodItem) => {
        const newDailyCalories = Math.max(0, dailyCalories - foodItem.calories);
        setDailyCalories(newDailyCalories);
        onCaloriesUpdate(newDailyCalories);
    };

    return (
        <div className="food-intake-container">
            <h2>Add Food</h2>
            <form onSubmit={addFood}>
                <div className='form-group'>
                    <input
                        type="text"
                        value={food}
                        onChange={(e) => setFood(e.target.value)}
                        placeholder="Food name"
                        required
                    />
                </div>

                <div className='form-group'>
                    <input
                        type="number"
                        value={calories}
                        onChange={(e) => setCalories(e.target.value)}
                        placeholder="Calories"
                        required
                    />
                </div>

                <button className='frontend-button' type="submit">Add Food</button>
            </form>

            <div className='food-favorites'>
                <h3>Favorite Foods</h3>
                <p>Daily Calories: {dailyCalories} kcal</p>
                {favorites.length === 0 ? (
                    <p>No favorite foods yet. Add some foods above!</p>
                ) : (
                    favorites.map((foodItem) => (
                        <div key={foodItem.id} className='food-intake-item'>
                            <div className="food-info">
                                <span className="food-name">{foodItem.name}</span>
                                <span className="food-calories">{foodItem.calories} cal</span>
                            </div>
                            <div className="food-actions">
                                <button 
                                    className="add-calories-btn"
                                    onClick={() => addCalories(foodItem)}
                                    title="Add to daily calories"
                                >
                                    +
                                </button>
                                <button 
                                    className="subtract-calories-btn"
                                    onClick={() => subtractCalories(foodItem)}
                                    title="Subtract from daily calories"
                                >
                                    -
                                </button>
                            </div>
                        </div>
                    ))
                )}
            </div>
        </div>
    );
}

export default FoodIntake;