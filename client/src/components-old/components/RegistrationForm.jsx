import React from 'react';

const RegistrationForm = () => {
  return (
    <div>
      <h2>Registration Form</h2>
      <form>
        <div className='form-group'>
          <input type="text" placeholder='Username' required />
        </div>

        <div className='form-group'>
          <input type="email" placeholder='Email' required />
        </div>

        <div className='form-group'>
          <input type="password" placeholder='Password' required />
        </div>

        <button className='frontend-button' type='submit'>Register</button>
      </form>
    </div>
  );
};

export default RegistrationForm;